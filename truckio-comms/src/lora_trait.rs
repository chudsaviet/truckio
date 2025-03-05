use embedded_hal_async::delay::DelayNs;
use lora_phy::LoRa;
use lora_phy::mod_params::{
    Bandwidth, CodingRate, ModulationParams, PacketParams, PacketStatus, RadioError, RxMode,
    SpreadingFactor,
};
use lora_phy::mod_traits::RadioKind;

pub trait LoRaTrait<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    fn create_modulation_params(
        &mut self,
        spreading_factor: SpreadingFactor,
        bandwidth: Bandwidth,
        coding_rate: CodingRate,
        frequency_in_hz: u32,
    ) -> Result<ModulationParams, RadioError>;

    fn create_rx_packet_params(
        &mut self,
        preamble_length: u16,
        implicit_header: bool,
        max_payload_length: u8,
        crc_on: bool,
        iq_inverted: bool,
        modulation_params: &ModulationParams,
    ) -> Result<PacketParams, RadioError>;

    async fn rx(
        &mut self,
        packet_params: &PacketParams,
        receiving_buffer: &mut [u8],
    ) -> Result<(u8, PacketStatus), RadioError>;

    async fn prepare_for_rx(
        &mut self,
        listen_mode: RxMode,
        mdltn_params: &ModulationParams,
        rx_pkt_params: &PacketParams,
    ) -> Result<(), RadioError>;
}

impl<RK, DLY> LoRaTrait<RK, DLY> for LoRa<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    fn create_rx_packet_params(
        &mut self,
        preamble_length: u16,
        implicit_header: bool,
        max_payload_length: u8,
        crc_on: bool,
        iq_inverted: bool,
        modulation_params: &ModulationParams,
    ) -> Result<PacketParams, RadioError> {
        self.create_rx_packet_params(
            preamble_length,
            implicit_header,
            max_payload_length,
            crc_on,
            iq_inverted,
            modulation_params,
        )
    }

    async fn rx(
        &mut self,
        packet_params: &PacketParams,
        receiving_buffer: &mut [u8],
    ) -> Result<(u8, PacketStatus), RadioError> {
        self.rx(packet_params, receiving_buffer).await
    }

    async fn prepare_for_rx(
        &mut self,
        listen_mode: RxMode,
        mdltn_params: &ModulationParams,
        rx_pkt_params: &PacketParams,
    ) -> Result<(), RadioError> {
        self.prepare_for_rx(listen_mode, mdltn_params, rx_pkt_params)
            .await
    }

    fn create_modulation_params(
        &mut self,
        spreading_factor: SpreadingFactor,
        bandwidth: Bandwidth,
        coding_rate: CodingRate,
        frequency_in_hz: u32,
    ) -> Result<ModulationParams, RadioError> {
        self.create_modulation_params(spreading_factor, bandwidth, coding_rate, frequency_in_hz)
    }
}
