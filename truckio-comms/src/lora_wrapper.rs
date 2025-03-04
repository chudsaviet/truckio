use embedded_hal_async::delay::DelayNs;
use lora_phy::LoRa;
use lora_phy::mod_params::{ModulationParams, PacketParams, PacketStatus, RadioError, RxMode};
use lora_phy::mod_traits::RadioKind;

pub struct LoRaWrapper<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    lora: LoRa<RK, DLY>,
}

impl<RK, DLY> LoRaWrapper<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    pub fn new(lora: LoRa<RK, DLY>) -> LoRaWrapper<RK, DLY> {
        LoRaWrapper { lora: lora }
    }

    pub fn create_rx_packet_params(
        &mut self,
        preamble_length: u16,
        implicit_header: bool,
        max_payload_length: u8,
        crc_on: bool,
        iq_inverted: bool,
        modulation_params: &ModulationParams,
    ) -> Result<PacketParams, RadioError> {
        self.lora.create_rx_packet_params(
            preamble_length,
            implicit_header,
            max_payload_length,
            crc_on,
            iq_inverted,
            modulation_params,
        )
    }

    pub async fn rx(
        &mut self,
        packet_params: &PacketParams,
        receiving_buffer: &mut [u8],
    ) -> Result<(u8, PacketStatus), RadioError> {
        self.lora.rx(packet_params, receiving_buffer).await
    }

    pub async fn prepare_for_rx(
        &mut self,
        listen_mode: RxMode,
        mdltn_params: &ModulationParams,
        rx_pkt_params: &PacketParams,
    ) -> Result<(), RadioError> {
        self.lora
            .prepare_for_rx(listen_mode, mdltn_params, rx_pkt_params)
            .await
    }
}
