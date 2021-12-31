// b: vérifie que r11 commence par HEIG-VD{

if (r11.startsWith("HEIG-VD{")) {
    goto L_0x00a;
}
else {
    return 0;
}
// c: vérifie que r11 termine par }

r0 = new StringBuilder(r11).reverse().toString().charAt(r1);
if (r0 == '}') {
    goto L_0x0020;
}
else {
    return 0;
}

// d: vérifie que la longueur de r11 vaille 35

if (r11.length() == 35) {
    goto L_0x0029;
}
else {
    return 0;
}

// e: vérifie que le flag à l'intérieur de HEIG-VD{...} commence par "this_is_"
//    (casse ignorée)

r0 = r11.toLowerCase().substring(8); // enlève HEIG-VD{
if (r0.startsWith("this_is_")) {
    goto L_0x003c;
}
else {
    return 0;
}

ver_cis
HEIG-VD{this_is_a_really_basic_rev}

// f: vérifie que la fin du flag corresponde à une certaine chaîne de caractère localisée

r0 = new StringBuilder(r11).reverse().toString().toLowerCase().substring(1); // enlève }
r4 = context.getString(2131427368); // get localized string with given id
if (r0.startsWith(r4)) {
    goto L_0x0060;
}
else {
    return 0;
}

// g: vérifie que le 18e caractère soit un _

if (r11.charAt(17) != '_') {
    return 0;
}

// h: vérifie que le 25e caractère soit un _
// X = 2, Y = 3, Z = 5

double r4 = 3.0
double r6 = 2.0
double r8 = 3.0
r6 = 8.0 // 2.0 ^ 3.0
r4 = 24.0 // 3.0 * 8.0
r0 = 24
r0 = r11.charAt(24);
r6 = 4.0
r4 = 16.0
r4 = 16
r4 = 17
r4 = ;
if (r11.charAt(17) == r11.charAt(24)) {
    goto L_0x0098;
}
else {
    return 0;
}

// i: vérifie que la partie du flag entre le 19e et 25e caractère inclus vaille
//    "really" (casse ignorée)

r0 = r11.toUpperCase();
r4 = 3
r5 = 2
r4 = 6
r5 = 3
r4 = 18
r5 = 5.0
r7 = 2.0
r5 = 25.0
r5 = 24
r0 = r0.substring(18, 25)
r0 = bam(r0)
if (r0 == "ERNYYL") {
    goto L_0x00cf;
}
else {
    return 0;
}

// j: vérifie que le 17e caractère vaille 'a'

r0 = r11.toLowerCase().charAt(16);
if (r0 == 'a') {
    goto L_0x00de; // ??
}
else {
    return 0;
}

// k: 26e char est égal au 27e + 1

r0 = r11.toUpperCase().charAt(25);
r4 = r11.toUpperCase().charAt(16); // 26 normalement
r4 =

// l: vérifie que le flag alterne majuscules et minuscules

r0 = "[A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_][A-Z_][a-z_]"
r4 = r11.length() - 1;
r2 = r11.substring(8, end) // flag entre { ... }
if (r2.matches(r0)) {
    return 1;
}
else {
    return 0;
}
