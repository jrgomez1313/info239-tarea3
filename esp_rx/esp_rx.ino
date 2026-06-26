#include <esp_now.h>
#include <WiFi.h>

typedef struct { char texto[200]; uint32_t contador; } Paquete;

void onRecibido(const esp_now_recv_info_t *info, const uint8_t *datos, int len) {
  Paquete pkt;
  memcpy(&pkt, datos, sizeof(pkt));
  Serial.printf("[#%u] Recibido: %s\n", pkt.contador, pkt.texto);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  esp_now_init();
  esp_now_register_recv_cb(onRecibido);
}

void loop() {}