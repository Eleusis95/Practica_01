/*
 * Encryption_and_Integrity_Layer.h
 *
 *  Created on: 6 feb. 2021
 *      Author: user
 */

#ifndef ENCRYPTION_AND_INTEGRITY_LAYER_H_
#define ENCRYPTION_AND_INTEGRITY_LAYER_H_

#include "Encryption_and_Integrity_Layer_Interface.h"
#include "Encryption_and_Integrity_Layer_Config.h"

typedef union { /*Variable para el manejo del CRC*/
	uint32_t crc32;
	uint8_t  strcrc[4];
}stCRC;

/*--------------------Functions------------------------*/

/*Initialitations*/
void Init_EncryptionAndIntegrity(); /*Initialize the basic seting for tcp conectivity and AES encription*/

/*Encryption*/
static size_t encrypt_msg(uint8_t *test_string, uint8_t padded_msg[]); /*Function to encrypt*/
static void decrypt_msg(uint8_t encrypted_msg[], size_t encrypted_msg_size); /*Function to decrypt*/

/*TCP/IP*/
int server_create(void *arg); /*Creación de server*/
err_t server_accept();/*aceptación del servicor creado*/
void close(void); /*Cierre de conexión*/

/*send/receive*/
void send_msg(uint8_t *test_string);
void receive_msg(void); /*Función para recibir mensajes, desnecrytación obtención de CRC renecritación y re-enviín de emnsaje,
basicamente es el echo*/

/*CRC*/
static uint32_t calculate_CRC(uint8_t padded_msg[],size_t padded_len); /*calculo de CRC*/
static u16_t concatenate_strToSend_CRC(stCRC CRC,uint8_t* msg); /*concatena el ensaje encryptado con el CRC antes de mandarlo*/
static void InitCrc32(CRC_Type *base, uint32_t seed);/*inicializa CRC32*/
static void get_CRC(uint8_t *data); /*saca el CRC del mensaje recibido*/

/*funciones que se usan como auxiliares en otras funciones*/
static size_t messageBody(uint8_t *data,uint8_t padded_msg[]); /*obtención del cuerpo del mensaje separando del CRC*/
static void substr(uint8_t *cad,uint8_t *sub,size_t ini,size_t fin);/*función para auxiliar a la función de obtencion del CRC del
menjsaje recibido*/

/**/

#endif /* ENCRYPTION_AND_INTEGRITY_LAYER_H_ */
