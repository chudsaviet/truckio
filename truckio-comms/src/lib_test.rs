#[cfg(test)]
mod tests {

    use crate::TruckIOComms;
    use crate::dummy_radio::DummyRadio;
    use crate::lora_trait::LoRaTrait;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use embassy_time::Delay;
    use embedded_hal_async::delay::DelayNs;
    use lora_phy::mod_params::{
        Bandwidth, CodingRate, ModulationParams, PacketParams, PacketStatus, RadioError, RxMode,
        SpreadingFactor,
    };
    use lora_phy::mod_traits::RadioKind;
    use mockall::predicate::*;
    use mockall::*;

    mock! {
        LoRa<RK, DLY> {}
        impl<RK, DLY> LoRaTrait<RK, DLY> for LoRa<RK, DLY>
        where
            RK: RadioKind,
            DLY: DelayNs, {
                fn create_modulation_params(
                    &mut self,
                    spreading_factor: SpreadingFactor,
                    bandwidth: Bandwidth,
                    coding_rate: CodingRate,
                    frequency_in_hz: u32,
                ) -> Result<ModulationParams, RadioError> ;


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
                ) -> Result<(u8, PacketStatus), RadioError> ;

                async fn prepare_for_rx(
                    &mut self,
                    listen_mode: RxMode,
                    mdltn_params: &ModulationParams,
                    rx_pkt_params: &PacketParams,
                ) -> Result<(), RadioError> ;
        }
    }
    #[test]
    fn test() {
        let mut mock_lora: MockLoRa<DummyRadio, Delay> = MockLoRa::new();
        mock_lora
            .expect_create_modulation_params()
            .return_once(ModulationParams { SpreadingFactor::_6,
                Bandwidth::_10KHz,
                CodingRate::_4_6,
                915000000,false, frequency_in_hz: 915000000 });
        let modulation_params: ModulationParams = match mock_lora.create_modulation_params(
            SpreadingFactor::_6,
            Bandwidth::_10KHz,
            CodingRate::_4_6,
            915000000,
        ) {
            Ok(x) => x,
            Err(_) => panic!(),
        };
        let mut truckio_comms: TruckIOComms<MockLoRa<DummyRadio, Delay>, DummyRadio, Delay> =
            match TruckIOComms::new(mock_lora, modulation_params, 0, [0; 32]) {
                Ok(x) => x,
                Err(_) => panic!(),
            };

        assert!(truckio_comms.address == 0);
    }
}
