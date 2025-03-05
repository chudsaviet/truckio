use lora_phy::{
    DelayNs, RxMode,
    mod_params::{
        Bandwidth, CodingRate, ModulationParams, PacketParams, PacketStatus, RadioError, RadioMode,
        SpreadingFactor,
    },
    mod_traits::{IrqState, RadioKind},
};

pub struct DummyRadio {}

impl RadioKind for DummyRadio {
    async fn init_lora(&mut self, is_public_network: bool) -> Result<(), RadioError> {
        unimplemented!()
    }

    fn create_modulation_params(
        &self,
        spreading_factor: SpreadingFactor,
        bandwidth: Bandwidth,
        coding_rate: CodingRate,
        frequency_in_hz: u32,
    ) -> Result<ModulationParams, RadioError> {
        unimplemented!()
    }

    fn create_packet_params(
        &self,
        preamble_length: u16,
        implicit_header: bool,
        payload_length: u8,
        crc_on: bool,
        iq_inverted: bool,
        modulation_params: &ModulationParams,
    ) -> Result<PacketParams, RadioError> {
        unimplemented!()
    }

    async fn reset(&mut self, delay: &mut impl DelayNs) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn ensure_ready(&mut self, mode: RadioMode) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_standby(&mut self) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_sleep(
        &mut self,
        warm_start_if_possible: bool,
        delay: &mut impl DelayNs,
    ) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_tx_rx_buffer_base_address(
        &mut self,
        tx_base_addr: usize,
        rx_base_addr: usize,
    ) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_tx_power_and_ramp_time(
        &mut self,
        output_power: i32,
        mdltn_params: Option<&ModulationParams>,
        is_tx_prep: bool,
    ) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_modulation_params(
        &mut self,
        mdltn_params: &ModulationParams,
    ) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_packet_params(&mut self, pkt_params: &PacketParams) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn calibrate_image(&mut self, frequency_in_hz: u32) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_channel(&mut self, frequency_in_hz: u32) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_payload(&mut self, payload: &[u8]) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn do_tx(&mut self) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn do_rx(&mut self, rx_mode: RxMode) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn get_rx_payload(
        &mut self,
        rx_pkt_params: &PacketParams,
        receiving_buffer: &mut [u8],
    ) -> Result<u8, RadioError> {
        unimplemented!()
    }

    async fn get_rx_packet_status(&mut self) -> Result<PacketStatus, RadioError> {
        unimplemented!()
    }

    async fn do_cad(&mut self, mdltn_params: &ModulationParams) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_irq_params(&mut self, radio_mode: Option<RadioMode>) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn set_tx_continuous_wave_mode(&mut self) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn await_irq(&mut self) -> Result<(), RadioError> {
        unimplemented!()
    }

    async fn process_irq_event(
        &mut self,
        radio_mode: RadioMode,
        cad_activity_detected: Option<&mut bool>,
        clear_interrupts: bool,
    ) -> Result<Option<IrqState>, RadioError> {
        unimplemented!()
    }
}
