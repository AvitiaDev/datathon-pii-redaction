#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char* ladas[] = { "449", "686", "612", "981", "961", "614", "55", "844", 
"312", "618", "720", "722", "729", "473", "747", "771", "33", "443", "777", 
"311", "81", "951", "220", "221", "222", "442", "446", "983", "440", "444", 
"667", "662", "993", "834", "246", "228", "990", "999", "492" };

const char* estados[] = {
    "AS","BC","BS","CC","CL","CM","CS","CH","DF","DG","GT","GR","HG","JC",
    "MC","MN","MS","NT","NL","OC","PL","QT","QR","SP","SL","SR","TC","TS",
    "TL","VZ","YN","ZS"
};

void generarNum(char* telefono) {
    sprintf(telefono, "%s%07d", ladas[rand() % 32], rand() % 1000000);
}

void generarNSS(char* nss) {
    sprintf(nss, "%02d", rand() % 100);
    sprintf(nss + 2, "%02d", rand() % 100);
    sprintf(nss + 4, "%02d", rand() % 100);
    sprintf(nss + 6, "%05d", rand() % 100000);
    nss[11] = '\0';
}

void generarCURP(char* curp) {
    const char* letras = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char* vocales = "AEIOU";
    int estadoIndex = rand() % 32;
    char ano = 1 + rand() % 2;

    curp[0] = letras[rand() % 26];
    curp[1] = vocales[rand() % 4];
    curp[2] = letras[rand() % 26];
    curp[3] = letras[rand() % 26];
    if (ano == 1) {
        ano = 19;
        sprintf(curp + 4, "%02d%02d%02d", ano, 1 + rand() % 12, 1 + rand() % 28);
    } else {
        sprintf(curp + 4, "%c%d%02d%02d", '0', 0 + rand() % 9, 1 + rand() % 12, 1 + rand() % 28);
    }

    curp[10] = (rand() % 2) ? 'H' : 'M';
    curp[11] = estados[estadoIndex][0];
    curp[12] = estados[estadoIndex][1];
    curp[13] = letras[rand() % 26];
    curp[14] = letras[rand() % 26];
    curp[15] = letras[rand() % 26];
    curp[16] = letras[rand() % 26];
    curp[17] = '0' + rand() % 10;
    curp[18] = '\0';
}

void generarRFC(char* rfc, char* curp) {
    const char* letras = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < 14; i++) {
        rfc[i] = curp[i];
    }
    rfc[10] = letras[rand() % 26];
    rfc[11] = '0' + rand() % 10;
    rfc[12] = letras[rand() % 26];
    rfc[13] = '\0';
}

void generarCorreo(char* correo, int id) {
    sprintf(correo, "trabajador%d@ejemplo.com", id);
}

int main() {
    srand(time(NULL));
    int cantidad = 5;
    for (int i = 1; i <= cantidad; i++) {
        char curp[19], nss[12], rfc[14], correo[50], numero[11];
        generarCURP(curp);
        generarNSS(nss);
        generarRFC(rfc, curp);
        generarCorreo(correo, i);
        generarNum(numero);

        printf("Registro %d:\n", i);
        printf("CURP: %s\n", curp);
        printf("NSS: %s\n", nss);
        printf("RFC: %s\n", rfc);
        printf("Numero telefonico: %s\n", numero);
        printf("Comprobante domicilio: Calle Falsa #%d, Col. Centro, Juárez, Chihuahua\n", 100 + i);
        printf("Correo: %s\n\n", correo);
    }
    return 0;
}
