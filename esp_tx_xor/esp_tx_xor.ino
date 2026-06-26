#include <esp_now.h>
#include <WiFi.h>
#include <string.h>

const uint8_t CLAVE[16] = {
  0x4C,0xAB,0x12,0xF3, 0x9E,0x71,0x3D,0x08,
  0xCC,0x55,0xA2,0x6B, 0x1F,0xE9,0x84,0x37
};

uint8_t macReceptor[] = {0x8c,0x94,0xdf,0x4c,0xb4,0xac};

typedef struct __attribute__((packed)) {
  uint8_t  payload[200];
  uint8_t  longitud;
  uint32_t id;
} PaqueteSeguro;

esp_now_peer_info_t peerInfo;

void xorCifrar(const uint8_t *entrada, uint8_t *salida,
               size_t lon, const uint8_t *clave, size_t lonClave) {
  for (size_t i = 0; i < lon; i++)
    salida[i] = entrada[i] ^ clave[i % lonClave];
}

void enviarSeguro(const char *mensaje) {
  PaqueteSeguro pkt;
  pkt.longitud = strlen(mensaje);
  pkt.id = millis();
  xorCifrar((uint8_t*)mensaje, pkt.payload,
            pkt.longitud, CLAVE, sizeof(CLAVE));

  esp_now_send(macReceptor, (uint8_t*)&pkt, sizeof(pkt));

  // Mostrar los bytes CIFRADos (ilegibles) en el Monitor de A
  Serial.printf("[TX] Texto original : %s\n", mensaje);
  Serial.print  ("[TX] Cifrado (hex) : ");
  for (uint8_t i = 0; i < pkt.longitud; i++)
    Serial.printf("%02X ", pkt.payload[i]);
  Serial.printf("\n[TX] Enviado: %d bytes\n\n", pkt.longitud);
}

void onEnviado(const wifi_tx_info_t *info, esp_now_send_status_t estado) {
  // Serial.println(estado == ESP_NOW_SEND_SUCCESS ? "OK" : "FALLO");
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  if (esp_now_init() != ESP_OK) {
    Serial.println("Error al inicializar ESP-NOW");
    return;
  }

  esp_now_register_send_cb(onEnviado);

  memcpy(peerInfo.peer_addr, macReceptor, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("Error al agregar peer");
    return;
  }

  Serial.println("Escribe un mensaje y presiona Enter para enviarlo:");
}

void loop() {
  if (Serial.available()) {
    String linea = Serial.readStringUntil('\n');
    linea.trim();                       // quita espacios y el \r final

    if (linea.length() > 0) {
      if (linea.length() > 199) {       // límite del payload
        linea = linea.substring(0, 199);
      }
      enviarSeguro(linea.c_str());
    }
  }
}