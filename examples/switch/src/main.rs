#![no_std]
#![no_main]

use embassy_executor::Spawner;
use {defmt_rtt as _, panic_probe as _};
use defmt::*;
use embassy_stm32::gpio::{Input, Level, Output, Pin, Pull};
use embassy_stm32::spi::{Config, Spi};
use embassy_time::Delay;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::sx126x::{Sx1262, Sx126x, TcxoCtrlVoltage};
use lora_phy::LoRa;
use lora_phy::{mod_params::*, sx126x};
use {defmt_rtt as _, panic_probe as _};

const LORA_FREQUENCY_IN_HZ: u32 = 903_900_000; // warning: set this appropriately for the region


#[embassy_executor::main]
async fn main(_spawner: Spawner) -> ! {
    let p = embassy_stm32::init(Default::default());
    let switch = Input::new(p.PA1, Pull::Up);

    // let nss = Output::new(p.PA1, Level::High);
    // let reset = Output::new(p.PA5.degrade(), Level::High);
    // let dio1 = Input::new(p.PA6.degrade(), Pull::None);
    // let busy = Input::new(p.PA7.degrade(), Pull::None);

    // let spi = Spi::new(
    //     p.SPI1,
    //     p.PIN_10,
    //     p.PIN_11,s
    //     p.PIN_12,
    //     p.DMA_CH0,
    //     p.DMA_CH1,
    //     Config::default(),
    // );
    // let spi = ExclusiveDevice::new(spi, nss, Delay).unwrap();

    // let config = sx126x::Config {
    //     chip: Sx1262,
    //     tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V7),
    //     use_dcdc: true,
    //     rx_boost: false,
    // };
    // let iv = GenericSx126xInterfaceVariant::new(reset, dio1, busy, None, None).unwrap();
    // let mut lora = LoRa::new(Sx126x::new(spi, iv, config), true, Delay).await.unwrap();

    // let mdltn_params = {
    //     match lora.create_modulation_params(
    //         SpreadingFactor::_10,
    //         Bandwidth::_250KHz,
    //         CodingRate::_4_8,
    //         LORA_FREQUENCY_IN_HZ,
    //     ) {
    //         Ok(mp) => mp,
    //         Err(err) => {
    //             info!("Radio error = {}", err);
    //             return;
    //         }
    //     }
    // };

    loop {
        if switch.is_high() {
            
        }
    }
}
