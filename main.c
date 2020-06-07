#include <stdio.h>
#include <esp/uart.h>

#include <FreeRTOS.h>
#include <task.h>
#include <espressif/esp_wifi.h>
#include <espressif/esp_sta.h>

#include <hackmdns.h>

int pairing=0;
void homekit_setup_mdns() { //homekit_server_t *server) {
    hack_mdns_configure_init("instancename",661,"modelname");

    // accessory model name (required)
    hack_mdns_add_txt("md", "%s", "modelname");
    // protocol version (required)
    hack_mdns_add_txt("pv", "1.0");
    // device ID (required)
    // should be in format XX:XX:XX:XX:XX:XX, otherwise devices will ignore it
    hack_mdns_add_txt("id", "%s", "AA:BB:CC:DD:EE:FF");
    // current configuration number (required)
    hack_mdns_add_txt("c#", "%u", 1234567890);
    // current state number (required)
    hack_mdns_add_txt("s#", "1");
    // feature flags (required if non-zero)
    //   bit 0 - supports HAP pairing. required for all HomeKit accessories
    //   bits 1-7 - reserved
    hack_mdns_add_txt("ff", "0");
    // status flags
    //   bit 0 - not paired
    //   bit 1 - not configured to join WiFi
    //   bit 2 - problem detected on accessory
    //   bits 3-7 - reserved
    hack_mdns_add_txt("sf", "%d", pairing);
    // accessory category identifier
    hack_mdns_add_txt("ci", "%d", 12345);
    hack_mdns_add_txt("sh", "%s", "ba64hash");
    
    hack_mdns_configure_finalize();
}

void server_task(void *arg) {
    hack_mdns_init();
    homekit_setup_mdns();
    vTaskDelay(10000);
    pairing=1;
    homekit_setup_mdns();
    vTaskDelete(NULL);
}

void user_init(void) {

    uart_set_baud(0, 115200);
/*    
    struct sdk_station_config wifi_config = {
    .ssid = "",
    .password = "",
    };
    sdk_wifi_set_opmode(STATION_MODE);
    sdk_wifi_station_set_config(&wifi_config);
    sdk_wifi_station_set_auto_connect(1);
    sdk_wifi_station_connect();
//*/
    xTaskCreate(server_task, "server", 512, NULL, 1, NULL);
}
