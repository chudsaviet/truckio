#![no_std]

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::heapless::Vec;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use defmt::*;
use embedded_hal_async::delay::DelayNs;
use lora_phy::mod_params::{ModulationParams, PacketParams};
use lora_phy::mod_traits::RadioKind;
use lora_phy::{LoRa, RxMode};
use lora_wrapper::LoRaWrapper;
use microbloom::MicroBloom;
use micropb::PbDecoder;

mod protos;
use protos::truckio_::comms_::RadioPacket;
use protos::truckio_::comms_::command_::Command;

mod lora_wrapper;

const BLOOM_FILTER_SIZE: usize = 256;
const BLOOM_FILTER_NUM_HASHES: u8 = 3;
const BLOOM_RESET_SIZE: u32 = 2000;

pub enum CommsError {
    Unspecified,
    RadioError,
    PbDecodeError,
    ToAddressWrongError,
    IncompletePacketError,
    IncompleteCommandError,
    DecryptError,
    ToVerificationError,
    MessageAlreadyReceivedError,
}

pub struct TruckIOComms<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    lora: LoRaWrapper<RK, DLY>,
    modulation_params: ModulationParams,
    rx_pkt_params: PacketParams,
    address: u32,
    cipher: ChaCha20Poly1305,
    bloom: MicroBloom<BLOOM_FILTER_SIZE, BLOOM_FILTER_NUM_HASHES>,
    bloom_counter: u32,
}

const PREAMBLE_LEN: u16 = 4;
const RADIO_RECEIVE_TIMEOUT_MS: u16 = 2000;

const RECEIVING_BUFFER_SIZE: usize = 64;

impl<RK, DLY> TruckIOComms<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    pub fn new(
        mut lora: LoRaWrapper<RK, DLY>,
        modulation_params: ModulationParams,
        address: u32,
        crypto_key: [u8; 32],
    ) -> Result<Self, CommsError> {
        let rx_pkt_params = {
            match lora.create_rx_packet_params(
                PREAMBLE_LEN as u16,         // preamble_length
                false,                       // implicit_header
                RECEIVING_BUFFER_SIZE as u8, // max_payload_length
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
        let bloom = MicroBloom::new();
        let bloom_counter: u32 = 0;

        let comms = Self {
            lora,
            modulation_params,
            rx_pkt_params,
            address,
            cipher,
            bloom,
            bloom_counter,
        };

        // Do any actions required for LoRa and/or crypto initialization.

        return Ok(comms);
    }

    async fn radio_receive(
        &mut self,
        buffer: &mut [u8; RECEIVING_BUFFER_SIZE],
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

    fn bloom_insert(&mut self, value: &[u8]) {
        if self.bloom_counter >= BLOOM_RESET_SIZE {
            self.bloom = MicroBloom::new();
        }
        self.bloom.insert(value);
    }

    pub async fn receive(&mut self) -> Result<Command, CommsError> {
        let mut buffer: [u8; RECEIVING_BUFFER_SIZE] = [00u8; RECEIVING_BUFFER_SIZE];

        let received_bytes: u8 = match self.radio_receive(&mut buffer).await {
            Ok(x) => x,
            Err(e) => return Err(e),
        };

        let mut rp_decoder = PbDecoder::new(&buffer[0..received_bytes as usize]);
        let radio_packet: RadioPacket = match rp_decoder.decode_message(received_bytes as usize) {
            Ok(x) => x,
            Err(_) => {
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

        if self.bloom.check(&radio_packet.nonce) {
            debug!(
                "Message with this nonce was already received. A bloom filter is used, therefore it can be a false positive."
            );
            return Err(CommsError::MessageAlreadyReceivedError);
        }
        self.bloom_insert(&radio_packet.nonce);

        let mut decrypt_buffer: Vec<u8, RECEIVING_BUFFER_SIZE> = Vec::new();

        match self.cipher.decrypt_in_place(
            Nonce::from_slice(&radio_packet.nonce),
            &radio_packet.payload,
            &mut decrypt_buffer,
        ) {
            Ok(_) => {}
            Err(_) => {
                error!("Decrypt error.");
                return Err(CommsError::DecryptError);
            }
        }

        let mut p_decoder = PbDecoder::new(&decrypt_buffer[0..radio_packet.payload.len()]);
        let command: Command = match p_decoder.decode_message(radio_packet.payload.len()) {
            Ok(x) => x,
            Err(_) => {
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

#[cfg(test)]
mod lib_test;
