#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// =====================================================================
//  ECDH (Curve25519) + AES-128-CTR sobre ESP-NOW  ·  INFO 239 Grupo 5
//  Versión corregida. Cambios marcados con  // [FIX]
// =====================================================================

enum TipoMensaje { MSG_HELLO, MSG_PUBKEY, MSG_DATA };

// [FIX] Se añade campo 'nonce' para AES-CTR (nonce único por mensaje)
struct __attribute__((packed)) PaqueteSeguro {
    uint8_t  tipo;
    uint16_t longitud;
    uint8_t  nonce[16];     // [FIX] nonce/IV que viaja con cada DATA
    uint8_t  payload[200];
};

// --- MACs de las dos placas (reemplaza por las tuyas reales) ---
const uint8_t MAC_PLACA_B[] = {0x8C, 0x94, 0xDF, 0x4C, 0xB4, 0xAC};
const uint8_t MAC_PLACA_A[] = {0x20, 0x9B, 0xA9, 0x60, 0xDD, 0xD0};
uint8_t macReceptor[6];

mbedtls_ecdh_context ecdh;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

uint8_t clave_aes_sesion[16];
bool clave_establecida = false;
bool soy_iniciador = false;

// [FIX] Estado del handshake (API alto nivel: generamos la pública UNA vez)
uint8_t mi_pub[64];
size_t  mi_pub_len = 0;
bool    mi_pub_enviada = false;

// [FIX] Trabajo pesado se difiere del callback al loop() vía banderas
volatile bool pendiente_enviar_pub = false;
volatile bool pendiente_calcular   = false;
uint8_t  pub_remota[64];
size_t   pub_remota_len = 0;

// --- Prototipos ---
void inicializar_ecdh();
void enviar_hello();
void enviar_pubkey();
void calcular_secreto();
void OnDataRecv(const uint8_t *mac, const uint8_t *data, int len);
void procesar_paquete(const uint8_t *data, int len);
void tuMecanismo_cifrar(const uint8_t *claro, uint8_t *cifrado, size_t len, uint8_t *nonce_out);
void tuMecanismo_descifrar(const uint8_t *cifrado, uint8_t *claro, size_t len, const uint8_t *nonce_in);
void enviarSeguro(const char *mensaje);

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    uint8_t macLocal[6];
    WiFi.macAddress(macLocal);
    Serial.print("MAC Local: ");
    for (int i = 0; i < 6; i++) {
        if (macLocal[i] < 0x10) Serial.print("0");
        Serial.print(macLocal[i], HEX);
        if (i < 5) Serial.print(":");
    }
    Serial.println();

    // Rol automático según la MAC física
    if (memcmp(macLocal, MAC_PLACA_A, 6) == 0) {
        soy_iniciador = true;
        memcpy(macReceptor, MAC_PLACA_B, 6);
        Serial.println("Rol: TRANSMISOR (Iniciador) -> Placa B");
    } else {
        soy_iniciador = false;
        memcpy(macReceptor, MAC_PLACA_A, 6);
        Serial.println("Rol: RECEPTOR (Respondedor) -> Placa A");
    }

    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

    if (esp_now_init() != ESP_OK) { Serial.println("Error esp_now_init"); return; }
    esp_now_register_recv_cb(esp_now_recv_cb_t(OnDataRecv));

    esp_now_peer_info_t peerInfo;
    memset(&peerInfo, 0, sizeof(peerInfo));
    memcpy(peerInfo.peer_addr, macReceptor, 6);
    peerInfo.channel = 1;
    peerInfo.encrypt = false;
    peerInfo.ifidx   = WIFI_IF_STA;
    if (esp_now_add_peer(&peerInfo) != ESP_OK) { Serial.println("Error add_peer"); return; }
    Serial.println("Peer OK.");

    inicializar_ecdh();   // [FIX] genera nuestro par de claves UNA sola vez

    if (soy_iniciador) {
        delay(3000);
        enviar_hello();
    }
}

// [FIX] loop() hace el trabajo pesado y reintenta el HELLO si se perdió
void loop() {
    static uint32_t ultimoHello = 0;

    if (pendiente_enviar_pub) { pendiente_enviar_pub = false; enviar_pubkey(); }

    if (pendiente_calcular) {
        pendiente_calcular = false;
        calcular_secreto();
        if (clave_establecida && soy_iniciador)
            enviarSeguro("Canal seguro abierto. Handshake OK.");
    }

    // Reintento de HELLO cada 1 s mientras no haya clave (paquetes ESP-NOW se pueden perder)
    if (soy_iniciador && !clave_establecida && millis() - ultimoHello > 1000) {
        ultimoHello = millis();
        enviar_hello();
    }

    if (clave_establecida && Serial.available() > 0) {
        String msg = Serial.readStringUntil('\n');
        msg.trim();
        if (msg.length() > 0) enviarSeguro(msg.c_str());
    }
}

// [FIX] API de alto nivel: setup + make_public una sola vez. Portable 2.x/3.x.
void inicializar_ecdh() {
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "ecdh_esp32_grupo5";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    int ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) { Serial.printf("Error ecdh_setup: %d\n", ret); return; }

    ret = mbedtls_ecdh_make_public(&ecdh, &mi_pub_len, mi_pub, sizeof(mi_pub),
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { Serial.printf("Error make_public: %d\n", ret); return; }

    Serial.println("[ECDH] Par de claves generado.");
}

void enviar_hello() {
    PaqueteSeguro pkt;
    pkt.tipo = MSG_HELLO;
    pkt.longitud = 0;
    esp_now_send(macReceptor, (uint8_t *)&pkt, sizeof(pkt));
    Serial.println("[Handshake] HELLO enviado.");
}

// [FIX] Envía nuestra pública YA generada (no la regenera cada vez)
void enviar_pubkey() {
    PaqueteSeguro pkt;
    pkt.tipo = MSG_PUBKEY;
    pkt.longitud = mi_pub_len;
    memcpy(pkt.payload, mi_pub, mi_pub_len);
    esp_now_send(macReceptor, (uint8_t *)&pkt, sizeof(pkt));
    mi_pub_enviada = true;
    Serial.println("[Handshake] Mi clave publica enviada.");
}

// [FIX] Cálculo del secreto con API de alto nivel (read_public + calc_secret)
void calcular_secreto() {
    long t0 = millis();

    int ret = mbedtls_ecdh_read_public(&ecdh, pub_remota, pub_remota_len);
    if (ret != 0) { Serial.printf("Error read_public: %d\n", ret); return; }

    uint8_t secreto[32];
    size_t slen = 0;
    ret = mbedtls_ecdh_calc_secret(&ecdh, &slen, secreto, sizeof(secreto),
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { Serial.printf("Error calc_secret: %d\n", ret); return; }

    memcpy(clave_aes_sesion, secreto, 16);   // primeros 16 bytes = clave AES-128
    clave_establecida = true;

    Serial.printf("[Handshake] Secreto derivado en %ld ms\n", millis() - t0);
    Serial.print("Clave AES de sesion: ");
    for (int i = 0; i < 16; i++) {
        if (clave_aes_sesion[i] < 0x10) Serial.print("0");
        Serial.print(clave_aes_sesion[i], HEX);
    }
    Serial.println();
    // >>> Verificacion: esta linea debe imprimir lo MISMO en ambas placas <<<
}

void OnDataRecv(const uint8_t *mac, const uint8_t *data, int len) {
    if (len < (int)sizeof(PaqueteSeguro)) return;
    procesar_paquete(data, len);   // [FIX] el callback solo copia y marca banderas
}

void procesar_paquete(const uint8_t *data, int len) {
    PaqueteSeguro *pkt = (PaqueteSeguro *)data;

    if (pkt->tipo == MSG_HELLO) {
        Serial.println("[Handshake] HELLO recibido -> enviare mi publica.");
        pendiente_enviar_pub = true;                 // el respondedor manda su pública
    }
    else if (pkt->tipo == MSG_PUBKEY) {
        Serial.println("[Handshake] Publica remota recibida.");
        // Guardamos la pública remota para procesarla en loop()
        pub_remota_len = pkt->longitud;
        memcpy(pub_remota, pkt->payload, pub_remota_len);

        // [FIX] Si soy el iniciador y aún no envié mi pública, mándala ahora.
        //       (este era el paso PUB_A que faltaba por completo)
        if (soy_iniciador && !mi_pub_enviada) pendiente_enviar_pub = true;

        pendiente_calcular = true;                   // calcular secreto en loop()
    }
    else if (pkt->tipo == MSG_DATA) {
        if (!clave_establecida) {
            Serial.println("Error: DATA sin clave establecida.");
            return;
        }
        uint8_t claro[201] = {0};
        size_t n = pkt->longitud;
        if (n > 200) n = 200;
        tuMecanismo_descifrar(pkt->payload, claro, n, pkt->nonce);
        Serial.print("Mensaje descifrado: ");
        Serial.println((char *)claro);
    }
}

// --- AES-128-CTR con nonce por mensaje ---------------------------------
// [FIX] cifrar genera un nonce aleatorio y lo devuelve para enviarlo
void tuMecanismo_cifrar(const uint8_t *claro, uint8_t *cifrado, size_t len, uint8_t *nonce_out) {
    mbedtls_ctr_drbg_random(&ctr_drbg, nonce_out, 16);   // nonce aleatorio unico

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, clave_aes_sesion, 128);

    uint8_t iv[16];
    memcpy(iv, nonce_out, 16);
    size_t nc_off = 0;
    uint8_t stream_block[16] = {0};

    mbedtls_aes_crypt_ctr(&aes, len, &nc_off, iv, stream_block, claro, cifrado);
    mbedtls_aes_free(&aes);
}

// [FIX] descifrar usa el nonce que llego en el paquete
void tuMecanismo_descifrar(const uint8_t *cifrado, uint8_t *claro, size_t len, const uint8_t *nonce_in) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, clave_aes_sesion, 128);   // CTR usa clave de cifrado en ambos sentidos

    uint8_t iv[16];
    memcpy(iv, nonce_in, 16);       // copiar: crypt_ctr modifica el buffer
    size_t nc_off = 0;
    uint8_t stream_block[16] = {0};

    mbedtls_aes_crypt_ctr(&aes, len, &nc_off, iv, stream_block, cifrado, claro);
    mbedtls_aes_free(&aes);
}

void enviarSeguro(const char *mensaje) {
    PaqueteSeguro pkt;
    pkt.tipo = MSG_DATA;
    pkt.longitud = strlen(mensaje);
    tuMecanismo_cifrar((const uint8_t *)mensaje, pkt.payload, pkt.longitud, pkt.nonce);
    esp_now_send(macReceptor, (uint8_t *)&pkt, sizeof(pkt));
    Serial.printf("[TX] Enviado cifrado (%d bytes)\n", pkt.longitud);
}