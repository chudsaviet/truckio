#![no_std]

use chacha20poly1305::aead::{Aead, AeadMutInPlace};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use defmt::*;
use embedded_hal_async::delay::DelayNs;
use lora_phy::mod_params::{ModulationParams, PacketParams};
use lora_phy::mod_traits::RadioKind;
use lora_phy::{LoRa, RxMode};
use micropb::PbDecoder;

mod protos;
use protos::truckio_::comms_::command_::Command;
use protos::truckio_::comms_::RadioPacket;

pub enum CommsError {
    Unspecified,
    RadioError,
    PbDecodeError,
    ToAddressWrongError,
    IncompletePacketError,
    IncompleteCommandError,
    DecryptError,
    ToVerificationError
}

pub struct TruckIOComms<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    lora: LoRa<RK, DLY>,
    modulation_params: ModulationParams,
    rx_pkt_params: PacketParams,
    address: u32,
    cipher: ChaCha20Poly1305,
}

const PREAMBLE_LEN: u16 = 4;
const RADIO_RECEIVE_TIMEOUT_MS: u16 = 2000;

// u8 is important since its the type used in LoRa library.
const RECEIVING_BUFFER_SIZE_BYTES: u8 = 128;

impl<RK, DLY> TruckIOComms<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    pub fn new(
        mut lora: LoRa<RK, DLY>,
        modulation_params: ModulationParams,
        address: u32,
        crypto_key: [u8; 32],
    ) -> Result<Self, CommsError> {
        let rx_pkt_params = {
            match lora.create_rx_packet_params(
                PREAMBLE_LEN as u16,         // preamble_length
                false,                       // implicit_header
                RECEIVING_BUFFER_SIZE_BYTES, // max_payload_length
                true,                        // crc_on
                false,                       // iq_inverted
                &modulation_params,          // modulation_params
            ) {
                Ok(pp) => pp,
                Err(err) => {
                    error!("Got RadioError: {}", err);
                    return Err(CommsError::RadioError);
                }
            }
        };

        let cipher = ChaCha20Poly1305::new(&crypto_key.into());

        let comms = Self {
            lora,
            modulation_params,
            rx_pkt_params,
            address,
            cipher,
        };

        // Do any actions required for LoRa and/or crypto initialization.

        return Ok(comms);
    }

    async fn radio_receive(
        &mut self,
        buffer: &mut [u8; RECEIVING_BUFFER_SIZE_BYTES as usize],
    ) -> Result<u8, CommsError> {
        match self
            .lora
            .prepare_for_rx(
                RxMode::Single(RADIO_RECEIVE_TIMEOUT_MS),
                &self.modulation_params,
                &self.rx_pkt_params,
            )
            .await
        {
            Ok(()) => {}
            Err(rerr) => {
                error!("Got RadioError: {}", rerr);
                return Err(CommsError::RadioError);
            }
        };
        match self.lora.rx(&self.rx_pkt_params, buffer).await {
            Ok(x) => {
                debug!("Received {} bytes. RSSI={} SNR={}", x.0, x.1.rssi, x.1.snr);
                return Ok(x.0);
            }
            Err(e) => {
                error!("Got RadioError: {}", e);
                return Err(CommsError::RadioError);
            }
        };
    }

    pub async fn receive(&mut self) -> Result<Command, CommsError> {
        let mut buffer: [u8; RECEIVING_BUFFER_SIZE_BYTES as usize] =
            [00u8; RECEIVING_BUFFER_SIZE_BYTES as usize];

        let received_bytes: u8 = match self.radio_receive(&mut buffer).await {
            Ok(x) => x,
            Err(e) => return Err(e),
        };

        let mut rp_decoder = PbDecoder::new(&buffer[0..received_bytes as usize]);
        let radio_packet: RadioPacket = match rp_decoder.decode_message(received_bytes as usize) {
            Ok(x) => x,
            Err(e) => {
                error!("Protobuf `RadioPacket` decode error.");
                return Err(CommsError::PbDecodeError);
            }
        };

        if !radio_packet._has.nonce() || !radio_packet._has.payload() || !radio_packet._has.to() {
            debug!("Received incomplete radio packet.");
            return Err(CommsError::IncompletePacketError);
        }

        if radio_packet.to != self.address {
            debug!("Received packed addressed to another node.");
            return Err(CommsError::ToAddressWrongError);
        }

        // TODO(chudsaviet): Add Bloom filter for nonces.

        let mut decrypt_buffer: [u8; RECEIVING_BUFFER_SIZE_BYTES as usize] =
            [00u8; RECEIVING_BUFFER_SIZE_BYTES as usize];

        match self.cipher.decrypt_in_place(
            &radio_packet.nonce.into(),
            &radio_packet.payload,
            &mut decrypt_buffer.into(),
        ) {
            Ok(_) => {},
            Err(_) => {
                error!("Decrypt error.");
                return Err(CommsError::DecryptError);
            },
        }

        let mut p_decoder = PbDecoder::new(&decrypt_buffer[0..radio_packet.payload.len()]);
        let command: Command = match p_decoder.decode_message(radio_packet.payload.len()) {
            Ok(x) => x,
            Err(e) => {
                error!("Protobuf `Command` decode error.");
                return Err(CommsError::PbDecodeError);
            }
        };

        if !command._has.to() || !command._has.r#type() {
            debug!("Received incomplete command.");
            return Err(CommsError::IncompleteCommandError);
        }

        if command.to != radio_packet.to {
            debug!("`to` field verification error. Probably radio packet was compromised.");
            return Err(CommsError::ToVerificationError);
        }

        Ok(command)
    }
}
