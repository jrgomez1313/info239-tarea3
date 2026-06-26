#include <esp_now.h>
#include <WiFi.h>
#include <string.h>

// ── Clave compartida (debe ser IDÉNTICA a la del transmisor) ──
const uint8_t CLAVE[16] = {
  0x4C,0xAB,0x12,0xF3, 0x9E,0x71,0x3D,0x08,
  0xCC,0x55,0xA2,0x6B, 0x1F,0xE9,0x84,0x37
};

// ── Estructura de paquete seguro (idéntica a la del transmisor) ──
typedef struct __attribute__((packed)) {
  uint8_t  payload[200];
  uint8_t  longitud;
  uint32_t id;
} PaqueteSeguro;

// ── Cifrar / Descifrar (XOR es simétrico) ──
void xorCifrar(const uint8_t *entrada, uint8_t *salida,
               size_t lon, const uint8_t *clave, size_t lonClave) {
  for (size_t i = 0; i < lon; i++)
    salida[i] = entrada[i] ^ clave[i % lonClave];
}

// ── Callback de recepción (core v3.x) ──
void onRecibido(const esp_now_recv_info_t *info, const uint8_t *datos, int len) {
  PaqueteSeguro pkt;
  memcpy(&pkt, datos, sizeof(pkt));

  uint8_t claro[201] = {0};   // +1 para el terminador nulo
  xorCifrar(pkt.payload, claro, pkt.longitud, CLAVE, sizeof(CLAVE));

  Serial.printf("[RX #%u] %s\n", pkt.id, claro);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  if (esp_now_init() != ESP_OK) {
    Serial.println("Error al inicializar ESP-NOW");
    return;
  }

  esp_now_register_recv_cb(onRecibido);
}

void loop() {
  // Todo el trabajo ocurre en el callback
}