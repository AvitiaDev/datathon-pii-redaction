/*
 * Generador de documentos sintéticos mexicanos (CV / solicitud de empleo)
 * con spans de PII "gold" para evaluar el detector.
 *
 * TODOS los datos son inventados. Los identificadores tienen formato válido
 * (CURP y RFC con dígito verificador, NSS con dígito Luhn, clave de elector INE)
 * pero no corresponden a ninguna persona real.
 *
 * Salida: JSONL, un documento por línea, mismo formato que AI4Privacy:
 *   {"id": "...", "source_text": "...", "privacy_mask": [{"start","end","label"}], "synthetic": true}
 * Los offsets son en CARACTERES (code points), como los usa Python.
 *
 * Uso:  gcc -O2 -o generador generador_sintetico.c
 *       ./generador 400 42 > mx_eval.jsonl        # cantidad, semilla
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- RNG determinista (igual en x86 y s390x) ---------- */
static unsigned long long rng_state = 42;
static unsigned rnd(void) {
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (unsigned)(rng_state >> 33);
}
static int rr(int n) { return (int)(rnd() % (unsigned)n); }
#define PICK(a) (a[rr((int)(sizeof(a) / sizeof(a[0])))])

/* ---------- Catálogos (display con acentos, ascii para claves) ---------- */
typedef struct { const char *disp, *ascii; char sex; } Nombre;
typedef struct { const char *disp, *ascii; } Apellido;

static const Nombre NOMBRES[] = {
    {"Ana","ANA",'M'},{"María","MARIA",'M'},{"Laura","LAURA",'M'},{"Sofía","SOFIA",'M'},
    {"Fernanda","FERNANDA",'M'},{"Guadalupe","GUADALUPE",'M'},{"Daniela","DANIELA",'M'},
    {"Valeria","VALERIA",'M'},{"Andrea","ANDREA",'M'},{"Lucía","LUCIA",'M'},{"Paola","PAOLA",'M'},
    {"Karla","KARLA",'M'},{"Elena","ELENA",'M'},{"Rocío","ROCIO",'M'},{"Itzel","ITZEL",'M'},
    {"Carlos","CARLOS",'H'},{"José","JOSE",'H'},{"Luis","LUIS",'H'},{"Juan","JUAN",'H'},
    {"Miguel","MIGUEL",'H'},{"Jorge","JORGE",'H'},{"Alejandro","ALEJANDRO",'H'},
    {"Ricardo","RICARDO",'H'},{"Héctor","HECTOR",'H'},{"Raúl","RAUL",'H'},{"Diego","DIEGO",'H'},
    {"Óscar","OSCAR",'H'},{"Eduardo","EDUARDO",'H'},{"Iván","IVAN",'H'},{"Emiliano","EMILIANO",'H'},
};
static const Apellido APELLIDOS[] = {
    {"Hernández","HERNANDEZ"},{"García","GARCIA"},{"Martínez","MARTINEZ"},{"López","LOPEZ"},
    {"González","GONZALEZ"},{"Rodríguez","RODRIGUEZ"},{"Pérez","PEREZ"},{"Sánchez","SANCHEZ"},
    {"Ramírez","RAMIREZ"},{"Torres","TORRES"},{"Flores","FLORES"},{"Rivera","RIVERA"},
    {"Gómez","GOMEZ"},{"Díaz","DIAZ"},{"Reyes","REYES"},{"Morales","MORALES"},{"Ortiz","ORTIZ"},
    {"Gutiérrez","GUTIERREZ"},{"Chávez","CHAVEZ"},{"Ruiz","RUIZ"},{"Soto","SOTO"},
    {"Mendoza","MENDOZA"},{"Castillo","CASTILLO"},{"Vázquez","VAZQUEZ"},{"Domínguez","DOMINGUEZ"},
    {"Aguilar","AGUILAR"},{"Medina","MEDINA"},{"Herrera","HERRERA"},{"Ochoa","OCHOA"},{"Holguín","HOLGUIN"},
};
static const char *CALLES[] = {
    "Av. Tecnológico","Av. de la Raza","Calle Vicente Guerrero","Av. Paseo Triunfo de la República",
    "Calle Ignacio Mejía","Av. Ejército Nacional","Calle Francisco Villa","Av. Insurgentes",
    "Calle Lerdo","Av. Manuel J. Clouthier","Calle Mariscal","Av. Valentín Fuentes",
    "Calle Constitución","Av. López Mateos","Calle Oro","Calle Santos Degollado",
};
static const char *COLONIAS[] = {
    "Centro","Pronaf","Campestre","Partido Romero","Bellavista","Riberas del Bravo",
    "Infonavit Casas Grandes","Senecú","El Mármol","Salvárcar","Los Nogales","Juárez Nuevo",
    "Partido Escobedo","Hidalgo","Melchor Ocampo","Las Torres",
};
static const char *PUESTOS[] = {
    "analista de datos","operador de producción","técnico de mantenimiento","auxiliar contable",
    "ingeniero de calidad","supervisor de línea","desarrollador de software","asistente de recursos humanos",
    "técnico en electrónica","coordinador de logística",
};
static const char *EMPRESAS[] = {
    "una maquiladora del Parque Industrial Antonio J. Bermúdez","una empresa de autopartes",
    "un despacho contable","una empresa de logística transfronteriza","una planta de electrónica",
    "una consultora de software","un centro de distribución",
};
static const char *DOMINIOS[] = {"gmail.com","hotmail.com","outlook.com","yahoo.com.mx","example.com"};
static const char *ESTADOS_CURP[] = {"CH","CH","CH","CH","DG","CL","SR","ZS","NL","DF","JC","VZ","CS"};
static const char *MESES[] = {"enero","febrero","marzo","abril","mayo","junio","julio",
                              "agosto","septiembre","octubre","noviembre","diciembre"};

/* ---------- Documento con spans ---------- */
#define MAXTXT 8192
#define MAXSP 64
typedef struct { int s, e; const char *label; } Span;
static char txt[MAXTXT]; static int tlen;
static Span sp[MAXSP]; static int nsp;

static int charpos(int byte_pos) {           /* bytes UTF-8 -> code points */
    int n = 0;
    for (int i = 0; i < byte_pos; i++) if ((txt[i] & 0xC0) != 0x80) n++;
    return n;
}
static void put(const char *s) {
    size_t l = strlen(s);
    if (tlen + (int)l >= MAXTXT) { fprintf(stderr, "doc too long\n"); exit(1); }
    memcpy(txt + tlen, s, l); tlen += (int)l; txt[tlen] = 0;
}
static void pii(const char *label, const char *s) {
    int b = tlen; put(s);
    sp[nsp].s = charpos(b); sp[nsp].e = charpos(tlen); sp[nsp].label = label; nsp++;
}
static void putf(const char *fmt, const char *a) { char b[512]; snprintf(b, sizeof b, fmt, a); put(b); }

/* ---------- Identificadores con formato válido ---------- */
static int is_vowel(char c) { return c=='A'||c=='E'||c=='I'||c=='O'||c=='U'; }
static char first_internal_vowel(const char *s) {
    for (int i = 1; s[i]; i++) if (is_vowel(s[i])) return s[i];
    return 'X';
}
static char first_internal_consonant(const char *s) {
    for (int i = 1; s[i]; i++) if (!is_vowel(s[i]) && s[i] >= 'A' && s[i] <= 'Z') return s[i];
    return 'X';
}

/* CURP: dígito verificador oficial (RENAPO), alfabeto con Ñ */
static int curp_val(char c) {
    const char *d = "0123456789ABCDEFGHIJKLMN#OPQRSTUVWXYZ";   /* '#' ocupa el lugar de Ñ */
    const char *p = strchr(d, c); return p ? (int)(p - d) : 0;
}
static void make_curp(char *out, const Nombre *n, const Apellido *a1, const Apellido *a2,
                      int yy, int mm, int dd, int year) {
    out[0] = a1->ascii[0]; out[1] = first_internal_vowel(a1->ascii);
    out[2] = a2->ascii[0]; out[3] = n->ascii[0];
    sprintf(out + 4, "%02d%02d%02d", yy, mm, dd);
    out[10] = n->sex;
    const char *e = PICK(ESTADOS_CURP); out[11] = e[0]; out[12] = e[1];
    out[13] = first_internal_consonant(a1->ascii);
    out[14] = first_internal_consonant(a2->ascii);
    out[15] = first_internal_consonant(n->ascii);
    out[16] = year < 2000 ? (char)('0' + rr(10)) : (char)('A' + rr(26)); /* homoclave siglo */
    int sum = 0;
    for (int i = 0; i < 17; i++) sum += curp_val(out[i]) * (18 - i);
    out[17] = (char)('0' + (10 - sum % 10) % 10);
    out[18] = 0;
}

/* RFC persona física: 10 de CURP + homoclave(2) + dígito verificador SAT */
static int rfc_val(char c) {
    const char *d = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ";
    if (c == ' ') return 37;
    const char *p = strchr(d, c); return p ? (int)(p - d) : 0;
}
static void make_rfc(char *out, const char *curp) {
    const char *hc = "123456789ABCDEFGHIJKLMNPQRSTUVWXYZ";
    memcpy(out, curp, 10);
    out[10] = hc[rr(34)]; out[11] = hc[rr(34)];
    int sum = 0;
    for (int i = 0; i < 12; i++) sum += rfc_val(out[i]) * (13 - i);
    int r = sum % 11, d = r == 0 ? 0 : 11 - r;
    out[12] = d == 10 ? 'A' : (char)('0' + d);
    out[13] = 0;
}

/* NSS IMSS: subdelegación(2) año alta(2) año nac(2) consecutivo(4) + dígito Luhn */
static void make_nss(char *out, int yy_nac, int year_nac) {
    int alta = (year_nac + 18 + rr(10)) % 100;
    sprintf(out, "%02d%02d%02d%04d", 1 + rr(98), alta, yy_nac, rr(10000));
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        int v = (out[i] - '0') * (i % 2 ? 2 : 1);
        sum += v / 10 + v % 10;
    }
    out[10] = (char)('0' + (10 - sum % 10) % 10); out[11] = 0;
}

/* Clave de elector INE (18): 6 letras + AAMMDD + entidad(2) + sexo + 3 dígitos */
static void make_ine(char *out, const Nombre *n, const Apellido *a1, const Apellido *a2,
                     int yy, int mm, int dd) {
    const char *src[3] = {a1->ascii, a2->ascii, n->ascii};
    for (int k = 0; k < 3; k++) {
        out[2*k] = src[k][0];
        char c = first_internal_consonant(src[k]);
        out[2*k+1] = c;
    }
    sprintf(out + 6, "%02d%02d%02d08%c%03d", yy, mm, dd, n->sex, rr(1000)); /* 08 = Chihuahua */
}

static void make_phone(char *out) {
    int a = 100 + rr(900), b = rr(10000);
    switch (rr(5)) {
        case 0: sprintf(out, "656 %03d %04d", a, b); break;
        case 1: sprintf(out, "+52 656 %03d %04d", a, b); break;
        case 2: sprintf(out, "(656) %03d-%04d", a, b); break;
        case 3: sprintf(out, "656%03d%04d", a, b); break;
        default: sprintf(out, "656-%03d-%04d", a, b); break;
    }
}

static void lower_ascii(char *dst, const char *src) {
    while (*src) { *dst++ = (*src >= 'A' && *src <= 'Z') ? (char)(*src + 32) : *src; src++; }
    *dst = 0;
}

/* ---------- JSON ---------- */
static void json_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') { putchar('\\'); putchar(*s); }
        else if (*s == '\n') { putchar('\\'); putchar('n'); }
        else putchar(*s);
    }
    putchar('"');
}

/* ---------- Plantillas ---------- */
static void gen_doc(int id) {
    tlen = 0; nsp = 0; txt[0] = 0;
    const Nombre *n = &PICK(NOMBRES);
    const Nombre *n2 = rr(3) == 0 ? &PICK(NOMBRES) : NULL;
    if (n2 && (n2 == n || n2->sex != n->sex)) n2 = NULL;
    const Apellido *a1 = &PICK(APELLIDOS), *a2 = &PICK(APELLIDOS);
    int year = 1965 + rr(40), yy = year % 100, mm = 1 + rr(12), dd = 1 + rr(28);

    char curp[19], rfc[14], nss[12], ine[19], tel[24], email[192], user[64];
    char calle[160], cp[8], num[16], fecha[64], fecha2[64];
    make_curp(curp, n, a1, a2, yy, mm, dd, year);
    make_rfc(rfc, curp);
    make_nss(nss, yy, year);
    make_ine(ine, n, a1, a2, yy, mm, dd);
    make_phone(tel);
    lower_ascii(user, n->ascii);
    char ap[48]; lower_ascii(ap, a1->ascii);
    switch (rr(3)) {
        case 0: sprintf(email, "%s.%s%02d@%s", user, ap, yy, PICK(DOMINIOS)); break;
        case 1: sprintf(email, "%c%s%d@%s", user[0], ap, rr(1000), PICK(DOMINIOS)); break;
        default: sprintf(email, "%s_%s@%s", user, ap, PICK(DOMINIOS)); break;
    }
    snprintf(calle, sizeof calle, "%s", PICK(CALLES));
    sprintf(num, "%d", 100 + rr(9800));
    sprintf(cp, "32%03d", rr(700));
    sprintf(fecha, "%02d/%02d/%04d", dd, mm, year);
    snprintf(fecha2, sizeof fecha2, "%d de %s de %d", dd, MESES[mm - 1], year);
    const char *col = PICK(COLONIAS), *puesto = PICK(PUESTOS);

    int tpl = rr(3);
    if (tpl == 0) {                          /* Solicitud de empleo, campos etiquetados */
        put("SOLICITUD DE EMPLEO\nPuesto solicitado: "); put(puesto); put("\n");
        put(rr(2) ? "Nombre: " : "Nombre completo: ");
        pii("GIVENNAME1", n->disp);
        if (n2) { put(" "); pii("GIVENNAME2", n2->disp); }
        put(" "); pii("LASTNAME1", a1->disp); put(" "); pii("LASTNAME2", a2->disp);
        put("\nFecha de nacimiento: "); pii("BOD", fecha);
        put("\nCURP: "); pii("CURP", curp);
        put("\nRFC: "); pii("RFC", rfc);
        put("\nNSS: "); pii("NSS", nss);
        put("\nClave de elector (INE): "); pii("INE", ine);
        put("\nTeléfono: "); pii("TEL", tel);
        put("\nCorreo electrónico: "); pii("EMAIL", email);
        put("\nDomicilio: "); { char s[200]; snprintf(s, sizeof s, "%s %s", calle, num); pii("STREET", s); }
        put(", Col. "); pii("SECADDRESS", col);
        put(", C.P. "); pii("POSTCODE", cp);
        put(", "); pii("CITY", "Ciudad Juárez"); put(", "); pii("STATE", "Chihuahua");
        put("\nEscolaridad: "); put(rr(2) ? "Licenciatura terminada" : "Preparatoria terminada");
        put("\nDisponibilidad: "); put(rr(2) ? "inmediata" : "a partir del próximo mes"); put("\n");
    } else if (tpl == 1) {                   /* CV narrativo */
        put("CURRICULUM VITAE\n\n");
        pii("GIVENNAME1", n->disp);
        if (n2) { put(" "); pii("GIVENNAME2", n2->disp); }
        put(" "); pii("LASTNAME1", a1->disp); put(" "); pii("LASTNAME2", a2->disp);
        put("\n"); { char s[200]; snprintf(s, sizeof s, "%s %s", calle, num); pii("STREET", s); }
        put(", "); pii("SECADDRESS", col); put(", "); pii("CITY", "Ciudad Juárez");
        put(", "); pii("STATE", "Chih."); put(" "); pii("POSTCODE", cp);
        put("\nTel. "); pii("TEL", tel); put(" | "); pii("EMAIL", email);
        put("\n\nPERFIL\nProfesional con experiencia como "); put(puesto);
        put(" en "); put(PICK(EMPRESAS)); put(". Nacido(a) el "); pii("BOD", fecha2); put(".");
        put("\n\nDATOS PERSONALES\nCURP "); pii("CURP", curp);
        put(" · RFC "); pii("RFC", rfc); put(" · NSS "); pii("NSS", nss);
        put("\n\nEXPERIENCIA\n"); put(rr(2) ? "Planta en Ciudad Juárez" : "Empresa del sector manufacturero"); put(", ");
        putf("%s, 2019 - actual.\n", puesto);
    } else {                                 /* Carta de presentación */
        put("Ciudad Juárez, Chihuahua, a 17 de octubre de 2026\n\nDepartamento de Recursos Humanos\nPresente\n\n");
        put("Por medio de la presente me permito solicitar el puesto de "); put(puesto);
        put(". Mi nombre es "); pii("GIVENNAME1", n->disp);
        put(" "); pii("LASTNAME1", a1->disp); put(" "); pii("LASTNAME2", a2->disp);
        put(", tengo experiencia en "); put(PICK(EMPRESAS));
        put(". Pueden contactarme al "); pii("TEL", tel); put(" o en "); pii("EMAIL", email);
        put(". Anexo copia de mi credencial para votar con clave de elector "); pii("INE", ine);
        put(" y mi CURP "); pii("CURP", curp); put(".\n\nAtentamente,\n");
        pii("GIVENNAME1", n->disp); put(" "); pii("LASTNAME1", a1->disp); put("\n");
    }

    printf("{\"id\": \"mx-%04d\", \"source_text\": ", id);
    json_str(txt);
    printf(", \"privacy_mask\": [");
    for (int i = 0; i < nsp; i++)
        printf("%s{\"start\": %d, \"end\": %d, \"label\": \"%s\"}", i ? ", " : "", sp[i].s, sp[i].e, sp[i].label);
    printf("], \"template\": %d, \"synthetic\": true}\n", tpl);
}

int main(int argc, char **argv) {
    int cantidad = argc > 1 ? atoi(argv[1]) : 400;
    rng_state = argc > 2 ? strtoull(argv[2], NULL, 10) : 42;
    for (int i = 1; i <= cantidad; i++) gen_doc(i);
    return 0;
}
