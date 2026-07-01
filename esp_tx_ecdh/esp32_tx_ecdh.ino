#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_idf_version.h"
#if ESP_IDF_VERSION_MAJOR >= 5
#include "esp_mac.h"
#endif
#include "mbedtls/ecdh.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// =====================================================================
//  ECDH (Curve25519) + AES-128-CTR sobre ESP-NOW  ·  INFO 239 Grupo 5
//  Versión corregida. Cambios marcados con  // [FIX]
// =====================================================================

// MSG_DATA conserva el valor 2 para no cambiar el formato anterior.
enum TipoMensaje { MSG_HELLO, MSG_PUBKEY, MSG_DATA, MSG_READY };

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
bool configuracion_valida = false;
bool peer_listo = false;
bool saludo_seguro_enviado = false;

// [FIX] Estado del handshake (API alto nivel: generamos la pública UNA vez)
uint8_t mi_pub[64];
size_t  mi_pub_len = 0;
bool    mi_pub_enviada = false;

// [FIX] Trabajo pesado se difiere del callback al loop() vía banderas
volatile bool pendiente_enviar_pub = false;
volatile bool pendiente_calcular   = false;
volatile bool pendiente_enviar_ready = false;
volatile bool pendiente_peer_ready   = false;
uint8_t  pub_remota[64];
size_t   pub_remota_len = 0;

// --- Prototipos ---
bool inicializar_ecdh();
void enviar_hello();
void enviar_pubkey();
void enviar_ready();
void calcular_secreto();
void OnDataRecv(const uint8_t *mac, const uint8_t *data, int len);
void procesar_paquete(const uint8_t *data, int len);
void tuMecanismo_cifrar(const uint8_t *claro, uint8_t *cifrado, size_t len, uint8_t *nonce_out);
void tuMecanismo_descifrar(const uint8_t *cifrado, uint8_t *claro, size_t len, const uint8_t *nonce_in);
void enviarSeguro(const char *mensaje);

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    uint8_t macLocal[6] = {0};

    // WiFi.macAddress() puede entregar 00:00:00:00:00:00 durante el arranque
    // en algunas combinaciones de placa/core. esp_read_mac() lee la MAC STA
    // directamente desde ESP-IDF y no depende de ese estado transitorio.
    esp_err_t macError = esp_read_mac(macLocal, ESP_MAC_WIFI_STA);
    bool macEnCero = true;
    for (int i = 0; i < 6; i++) macEnCero &= (macLocal[i] == 0);

    // Respaldo por si el core no pudo obtenerla desde eFuse.
    if (macError != ESP_OK || macEnCero) {
        macError = esp_wifi_get_mac(WIFI_IF_STA, macLocal);
    }

    Serial.print("MAC Local: ");
    for (int i = 0; i < 6; i++) {
        if (macLocal[i] < 0x10) Serial.print("0");
        Serial.print(macLocal[i], HEX);
        if (i < 5) Serial.print(":");
    }
    Serial.println();

    if (macError != ESP_OK) {
        Serial.printf("ERROR: no se pudo leer la MAC STA (%d).\n", macError);
        return;
    }

    // Rol automático según la MAC física. Una MAC desconocida ya no cae
    // silenciosamente en RECEPTOR, porque eso ocultaba el problema real.
    if (memcmp(macLocal, MAC_PLACA_A, 6) == 0) {
        soy_iniciador = true;
        memcpy(macReceptor, MAC_PLACA_B, 6);
        Serial.println("Rol: TRANSMISOR (Iniciador) -> Placa B");
    } else if (memcmp(macLocal, MAC_PLACA_B, 6) == 0) {
        soy_iniciador = false;
        memcpy(macReceptor, MAC_PLACA_A, 6);
        Serial.println("Rol: RECEPTOR (Respondedor) -> Placa A");
    } else {
        Serial.println("ERROR: la MAC local no coincide con MAC_PLACA_A ni MAC_PLACA_B.");
        Serial.println("Actualiza esas dos constantes con las MAC impresas por cada placa.");
        return;
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

    if (!inicializar_ecdh()) return; // genera nuestro par de claves UNA sola vez
    configuracion_valida = true;

    if (soy_iniciador) {
        delay(3000);
        enviar_hello();
    }
}

// [FIX] loop() hace el trabajo pesado y reintenta el HELLO si se perdió
void loop() {
    static uint32_t ultimoHello = 0;

    if (!configuracion_valida) {
        delay(1000);
        return;
    }

    if (pendiente_enviar_pub) { pendiente_enviar_pub = false; enviar_pubkey(); }

    if (pendiente_calcular) {
        pendiente_calcular = false;
        if (!clave_establecida) calcular_secreto();
        if (clave_establecida && !soy_iniciador) pendiente_enviar_ready = true;
    }

    if (pendiente_enviar_ready) {
        pendiente_enviar_ready = false;
        enviar_ready();
    }

    if (pendiente_peer_ready) {
        pendiente_peer_ready = false;
        if (soy_iniciador && clave_establecida) {
            peer_listo = true;
            if (!saludo_seguro_enviado) {
                saludo_seguro_enviado = true;
                enviarSeguro("Canal seguro abierto. Handshake OK.");
            }
        }
    }

    // Hasta recibir READY se reintenta HELLO: así también se recupera un
    // READY perdido sin enviar DATA antes de que el receptor tenga la clave.
    if (soy_iniciador && !peer_listo && millis() - ultimoHello > 1000) {
        ultimoHello = millis();
        enviar_hello();
    }

    bool canalListo = clave_establecida && (!soy_iniciador || peer_listo);
    if (canalListo && Serial.available() > 0) {
        String msg = Serial.readStringUntil('\n');
        msg.trim();
        if (msg.length() > 0) enviarSeguro(msg.c_str());
    }
}

// [FIX] API de alto nivel: setup + make_public una sola vez. Portable 2.x/3.x.
bool inicializar_ecdh() {
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "ecdh_esp32_grupo5";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) { Serial.printf("Error ctr_drbg_seed: %d\n", ret); return false; }

    ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) { Serial.printf("Error ecdh_setup: %d\n", ret); return false; }

    ret = mbedtls_ecdh_make_public(&ecdh, &mi_pub_len, mi_pub, sizeof(mi_pub),
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { Serial.printf("Error make_public: %d\n", ret); return false; }

    Serial.printf("[ECDH] Par de claves generado. Publica serializada: %u bytes.\n",
                  (unsigned)mi_pub_len);
    return true;
}

void enviar_hello() {
    PaqueteSeguro pkt = {};
    pkt.tipo = MSG_HELLO;
    pkt.longitud = 0;
    esp_now_send(macReceptor, (uint8_t *)&pkt, sizeof(pkt));
    Serial.println("[Handshake] HELLO enviado.");
}

// [FIX] Envía nuestra pública YA generada (no la regenera cada vez)
void enviar_pubkey() {
    PaqueteSeguro pkt = {};
    pkt.tipo = MSG_PUBKEY;
    pkt.longitud = mi_pub_len;
    memcpy(pkt.payload, mi_pub, mi_pub_len);
    esp_now_send(macReceptor, (uint8_t *)&pkt, sizeof(pkt));
    mi_pub_enviada = true;
    Serial.println("[Handshake] Mi clave publica enviada.");
}

void enviar_ready() {
    PaqueteSeguro pkt = {};
    pkt.tipo = MSG_READY;
    pkt.longitud = 0;
    esp_now_send(macReceptor, (uint8_t *)&pkt, sizeof(pkt));
    Serial.println("[Handshake] READY enviado.");
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
    const PaqueteSeguro *pkt = (const PaqueteSeguro *)data;

    if (pkt->tipo == MSG_HELLO) {
        if (soy_iniciador) return;

        if (clave_establecida) {
            // El iniciador puede estar reintentando porque se perdió READY.
            pendiente_enviar_ready = true;
        } else {
            Serial.println("[Handshake] HELLO recibido -> enviare mi publica.");
            pendiente_enviar_pub = true;
        }
    }
    else if (pkt->tipo == MSG_PUBKEY) {
        Serial.println("[Handshake] Publica remota recibida.");

        if (clave_establecida) {
            if (soy_iniciador && !peer_listo) {
                // Puede haberse perdido nuestra PUBKEY: reenviarla permite que
                // el respondedor termine el intercambio y conteste READY.
                pendiente_enviar_pub = true;
            } else if (!soy_iniciador) {
                pendiente_enviar_ready = true;
            }
            return;
        }

        // make_public/read_public usan una clave Curve25519 serializada. En la
        // API ECDH clásica de MbedTLS normalmente ocupa 33 bytes, no 32.
        // Se compara con lo que realmente generó esta versión de la librería.
        size_t longitudRecibida = pkt->longitud;
        if (longitudRecibida == 0 ||
            longitudRecibida > sizeof(pub_remota) ||
            longitudRecibida != mi_pub_len) {
            Serial.printf("[Handshake] Longitud publica invalida: %u; esperada: %u.\n",
                          (unsigned)longitudRecibida, (unsigned)mi_pub_len);
            return;
        }

        // Guardamos la pública remota para procesarla en loop()
        pub_remota_len = longitudRecibida;
        memcpy(pub_remota, pkt->payload, pub_remota_len);

        // [FIX] Si soy el iniciador y aún no envié mi pública, mándala ahora.
        //       (este era el paso PUB_A que faltaba por completo)
        if (soy_iniciador && !mi_pub_enviada) pendiente_enviar_pub = true;

        pendiente_calcular = true;                   // calcular secreto en loop()
    }
    else if (pkt->tipo == MSG_READY) {
        pendiente_peer_ready = true;
        Serial.println("[Handshake] READY recibido.");
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
    PaqueteSeguro pkt = {};
    pkt.tipo = MSG_DATA;
    size_t longitud = strlen(mensaje);
    if (longitud > sizeof(pkt.payload)) longitud = sizeof(pkt.payload);
    pkt.longitud = longitud;
    tuMecanismo_cifrar((const uint8_t *)mensaje, pkt.payload, pkt.longitud, pkt.nonce);
    esp_now_send(macReceptor, (uint8_t *)&pkt, sizeof(pkt));
    Serial.printf("[TX] Enviado cifrado (%d bytes)\n", pkt.longitud);
}
