#![no_std]

use chacha20poly1305::aead::heapless::Vec;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use defmt::*;
use embedded_hal_async::delay::DelayNs;
use frand::Rand;
use lora_phy::mod_params::{ModulationParams, PacketParams};
use lora_phy::mod_traits::RadioKind;
use lora_phy::{LoRa, RxMode};
use microbloom::MicroBloom;
use micropb::MessageEncode;
use micropb::{heapless::Vec as MicropbVec, PbDecoder, PbEncoder};

mod protos;
use protos::truckio_::comms_::command_::Command;
use protos::truckio_::comms_::RadioPacket;

const BLOOM_FILTER_SIZE: usize = 256;
const BLOOM_FILTER_NUM_HASHES: u8 = 3;
const BLOOM_HARD_RESET_LIMIT: u32 = 4000;
// Bloom filter shall randomly reset approximately once per 2000 inserts.
const BLOOM_RESET_PROBABILITY_MILLIPERCENT: u32 = 5;
const NONCE_LENGTH: usize = 12;
const PB_ENCODER_MAX_BYTES: usize = 128;
const PAYLOAD_MAX_SIZE: usize = 64;
const PACKET_MAX_SIZE: usize = 128;

#[derive(Debug, Format)]
pub enum CommsError {
    Unspecified,
    RadioError,
    PbDecodeError,
    PbEncodeError,
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
    lora: LoRa<RK, DLY>,
    rand: Rand,
    pb_encoder: PbEncoder<MicropbVec<u8, PB_ENCODER_MAX_BYTES>>,
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
        mut lora: LoRa<RK, DLY>,
        mut rand: Rand,
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
        let pb_encoder = PbEncoder::new(MicropbVec::<u8, PB_ENCODER_MAX_BYTES>::new());

        let comms = Self {
            lora,
            rand,
            pb_encoder,
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
        // To avoid Bloom filter overflow, we reset it when it grows too much.
        // To make reset less perdictable, we also reset it on each insert with some probability.
        if self.bloom_counter >= BLOOM_HARD_RESET_LIMIT
            || self.rand.gen_range(0..10000u32) < BLOOM_RESET_PROBABILITY_MILLIPERCENT
        {
            self.bloom = MicroBloom::new();
            self.bloom_counter = 0;
        }
        self.bloom_counter += 1;
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
            debug!("Message with this nonce was already received. A bloom filter is used, therefore it can be a false positive.");
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

    fn replace_rand(&mut self, rand: Rand) {
        self.rand = rand;
    }

    fn gen_nonce(&mut self) -> MicropbVec<u8, NONCE_LENGTH> {
        let mut nonce: MicropbVec<u8, NONCE_LENGTH> = MicropbVec::new();

        for i in 1..(NONCE_LENGTH / 4) {
            let num: u32 = self.rand.r#gen();
            nonce.extend(num.to_le_bytes());
        }

        nonce
    }

    fn build_packet(&mut self, command: Command, to: u32) -> Result<RadioPacket, CommsError> {
        match command.encode(&mut self.pb_encoder) {
            Ok(x) => x,
            Err(e) => {
                error!("Can't encode Command Protobuf! {}", e);
                return Err(CommsError::PbEncodeError);
            }
        };

        let mut payload: MicropbVec<u8, PAYLOAD_MAX_SIZE> = MicropbVec::new();
        match payload.extend_from_slice(self.pb_encoder.as_writer()) {
            Ok(_) => {}
            Err(e) => {
                error!("Command serialization error. {}", e);
                return Err(CommsError::PbEncodeError);
            }
        }

        let packet: RadioPacket = RadioPacket {
            payload,
            nonce: self.gen_nonce(),
            to,
            ..Default::default()
        };

        return Ok(packet);
    }

    fn build_encoded_packet(
        &mut self,
        command: Command,
        to: u32,
    ) -> Result<MicropbVec<u8, PACKET_MAX_SIZE>, CommsError> {
        let packet = match self.build_packet(command, to) {
            Ok(x) => x,
            Err(e) => {
                error!("Can't build packet. {}", e);
                return Err(e);
            }
        };

        match packet.encode(&mut self.pb_encoder) {
            Ok(x) => x,
            Err(e) => {
                error!("Can't encode RadioPacket Protobuf! {}", e);
                return Err(CommsError::PbEncodeError);
            }
        };

        let mut encoded_packet: MicropbVec<u8, PACKET_MAX_SIZE> = MicropbVec::new();
        match encoded_packet.extend_from_slice(self.pb_encoder.as_writer()) {
            Ok(_) => {}
            Err(e) => {
                error!("Command serialization error. {}", e);
                return Err(CommsError::PbEncodeError);
            }
        };
        return Ok(encoded_packet);
    }

    fn transmit(&mut self, command: Command, address: u32) -> Result<(), CommsError> {
        Ok(())
    }
}
