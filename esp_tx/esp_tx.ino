#include <esp_now.h>
#include <WiFi.h>
// ⚠ Reemplaza con la MAC real de tu ESP32-B
uint8_t macReceptor[] = {0x8c,0x94,0xdf,0x4c,0xb4,0xac};
typedef struct { char texto[200]; uint32_t contador; } Paquete;

void onEnviado(const wifi_tx_info_t *info, esp_now_send_status_t estado) {
  Serial.println(estado == ESP_NOW_SEND_SUCCESS ? "OK" : "FALLO");
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  esp_now_init();
  esp_now_register_send_cb(onEnviado);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, macReceptor, 6);
  peer.channel = 0; peer.encrypt = false;
  esp_now_add_peer(&peer);
}

void loop() {
  static uint32_t cnt = 0;
  Paquete pkt;
  snprintf(pkt.texto, sizeof(pkt.texto), "Hola desde ESP32-A! Grupo 5");
  pkt.contador = cnt++;
  esp_now_send(macReceptor, (uint8_t*)&pkt, sizeof(pkt));
  delay(2000);
}