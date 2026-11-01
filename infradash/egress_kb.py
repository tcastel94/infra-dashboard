"""Données de référence des flux sortants : pays, régions cloud, classification des services.

Tout est embarqué (aucune requête réseau) : centroïdes des pays, villes des régions AWS / Google Cloud,
règles de classification (ASN, plages, ports, PTR, domaines connus) et conseils de blocage par service.
"""
import re

# --- Catégories (libellé FR + couleur de la charte) -----------------------------------------------
CATEGORIES = {
    "dns": ("DNS", "#64D2FF"),
    "cloud": ("Cloud / hébergeur", "#4A9EFF"),
    "cdn": ("CDN", "#8E8E93"),
    "vpn": ("VPN / tunnel", "#30D158"),
    "messagerie": ("Messagerie", "#BF5AF2"),
    "iot-camera": ("Caméras / IoT", "#FF9F0A"),
    "push": ("Notifications push", "#FFD60A"),
    "maj-logiciels": ("Mises à jour / dépôts", "#30D158"),
    "stockage": ("Stockage en ligne", "#64D2FF"),
    "streaming": ("Médias / métadonnées", "#FF375F"),
    "pub-tracking": ("Pub / télémétrie", "#FF453A"),
    "ia": ("IA (API)", "#BF5AF2"),
    "telechargement": ("Téléchargement (Usenet)", "#FF9F0A"),
    "systeme": ("Services système", "#8E8E93"),
    "inconnu": ("Inconnu", "#98989f"),
}

# --- Pays : ISO alpha-2 -> (lat, lon, nom FR) ; centroïdes approximatifs -------------------------
_COUNTRIES = """
AD|42.55|1.60|Andorre
AE|23.42|53.85|Émirats arabes unis
AF|33.94|67.71|Afghanistan
AG|17.06|-61.80|Antigua-et-Barbuda
AI|18.22|-63.07|Anguilla
AL|41.15|20.17|Albanie
AM|40.07|45.04|Arménie
AO|-11.20|17.87|Angola
AQ|-75.25|-0.07|Antarctique
AR|-38.42|-63.62|Argentine
AS|-14.27|-170.13|Samoa américaines
AT|47.52|14.55|Autriche
AU|-25.27|133.78|Australie
AW|12.52|-69.97|Aruba
AX|60.18|19.92|Åland
AZ|40.14|47.58|Azerbaïdjan
BA|43.92|17.68|Bosnie-Herzégovine
BB|13.19|-59.54|Barbade
BD|23.68|90.36|Bangladesh
BE|50.50|4.47|Belgique
BF|12.24|-1.56|Burkina Faso
BG|42.73|25.49|Bulgarie
BH|25.93|50.64|Bahreïn
BI|-3.37|29.92|Burundi
BJ|9.31|2.32|Bénin
BL|17.90|-62.83|Saint-Barthélemy
BM|32.32|-64.76|Bermudes
BN|4.54|114.73|Brunei
BO|-16.29|-63.59|Bolivie
BQ|12.18|-68.25|Pays-Bas caribéens
BR|-14.24|-51.93|Brésil
BS|25.03|-77.40|Bahamas
BT|27.51|90.43|Bhoutan
BV|-54.42|3.41|Île Bouvet
BW|-22.33|24.68|Botswana
BY|53.71|27.95|Biélorussie
BZ|17.19|-88.50|Belize
CA|56.13|-106.35|Canada
CC|-12.16|96.87|Îles Cocos
CD|-4.04|21.76|RD Congo
CF|6.61|20.94|Centrafrique
CG|-0.23|15.83|Congo
CH|46.82|8.23|Suisse
CI|7.54|-5.55|Côte d'Ivoire
CK|-21.24|-159.78|Îles Cook
CL|-35.68|-71.54|Chili
CM|7.37|12.35|Cameroun
CN|35.86|104.20|Chine
CO|4.57|-74.30|Colombie
CR|9.75|-83.75|Costa Rica
CU|21.52|-77.78|Cuba
CV|16.00|-24.01|Cap-Vert
CW|12.17|-68.99|Curaçao
CX|-10.45|105.69|Île Christmas
CY|35.13|33.43|Chypre
CZ|49.82|15.47|Tchéquie
DE|51.17|10.45|Allemagne
DJ|11.83|42.59|Djibouti
DK|56.26|9.50|Danemark
DM|15.41|-61.37|Dominique
DO|18.74|-70.16|République dominicaine
DZ|28.03|1.66|Algérie
EC|-1.83|-78.18|Équateur
EE|58.60|25.01|Estonie
EG|26.82|30.80|Égypte
EH|24.22|-12.89|Sahara occidental
ER|15.18|39.78|Érythrée
ES|40.46|-3.75|Espagne
ET|9.15|40.49|Éthiopie
FI|61.92|25.75|Finlande
FJ|-16.58|179.41|Fidji
FK|-51.80|-59.52|Îles Malouines
FM|7.43|150.55|Micronésie
FO|61.89|-6.91|Îles Féroé
FR|46.23|2.21|France
GA|-0.80|11.61|Gabon
GB|55.38|-3.44|Royaume-Uni
GD|12.26|-61.60|Grenade
GE|42.32|43.36|Géorgie
GF|3.93|-53.13|Guyane
GG|49.47|-2.59|Guernesey
GH|7.95|-1.02|Ghana
GI|36.14|-5.35|Gibraltar
GL|71.71|-42.60|Groenland
GM|13.44|-15.31|Gambie
GN|9.95|-9.70|Guinée
GP|16.00|-61.73|Guadeloupe
GQ|1.65|10.27|Guinée équatoriale
GR|39.07|21.82|Grèce
GS|-54.43|-36.59|Géorgie du Sud
GT|15.78|-90.23|Guatemala
GU|13.44|144.79|Guam
GW|11.80|-15.18|Guinée-Bissau
GY|4.86|-58.93|Guyana
HK|22.40|114.11|Hong Kong
HM|-53.08|73.50|Îles Heard-et-MacDonald
HN|15.20|-86.24|Honduras
HR|45.10|15.20|Croatie
HT|18.97|-72.29|Haïti
HU|47.16|19.50|Hongrie
ID|-0.79|113.92|Indonésie
IE|53.41|-8.24|Irlande
IL|31.05|34.85|Israël
IM|54.24|-4.55|Île de Man
IN|20.59|78.96|Inde
IO|-6.34|71.88|Territoire britannique de l'océan Indien
IQ|33.22|43.68|Irak
IR|32.43|53.69|Iran
IS|64.96|-19.02|Islande
IT|41.87|12.57|Italie
JE|49.21|-2.13|Jersey
JM|18.11|-77.30|Jamaïque
JO|30.59|36.24|Jordanie
JP|36.20|138.25|Japon
KE|-0.02|37.91|Kenya
KG|41.20|74.77|Kirghizistan
KH|12.57|104.99|Cambodge
KI|-3.37|-168.73|Kiribati
KM|-11.88|43.87|Comores
KN|17.36|-62.78|Saint-Christophe-et-Niévès
KP|40.34|127.51|Corée du Nord
KR|35.91|127.77|Corée du Sud
KW|29.31|47.48|Koweït
KY|19.51|-80.57|Îles Caïmans
KZ|48.02|66.92|Kazakhstan
LA|19.86|102.50|Laos
LB|33.85|35.86|Liban
LC|13.91|-60.98|Sainte-Lucie
LI|47.17|9.56|Liechtenstein
LK|7.87|80.77|Sri Lanka
LR|6.43|-9.43|Liberia
LS|-29.61|28.23|Lesotho
LT|55.17|23.88|Lituanie
LU|49.82|6.13|Luxembourg
LV|56.88|24.60|Lettonie
LY|26.34|17.23|Libye
MA|31.79|-7.09|Maroc
MC|43.75|7.41|Monaco
MD|47.41|28.37|Moldavie
ME|42.71|19.37|Monténégro
MF|18.07|-63.05|Saint-Martin
MG|-18.77|46.87|Madagascar
MH|7.13|171.18|Îles Marshall
MK|41.61|21.75|Macédoine du Nord
ML|17.57|-4.00|Mali
MM|21.91|95.96|Birmanie
MN|46.86|103.85|Mongolie
MO|22.20|113.54|Macao
MP|17.33|145.38|Îles Mariannes du Nord
MQ|14.64|-61.02|Martinique
MR|21.01|-10.94|Mauritanie
MS|16.74|-62.19|Montserrat
MT|35.94|14.38|Malte
MU|-20.35|57.55|Maurice
MV|3.20|73.22|Maldives
MW|-13.25|34.30|Malawi
MX|23.63|-102.55|Mexique
MY|4.21|101.98|Malaisie
MZ|-18.67|35.53|Mozambique
NA|-22.96|18.49|Namibie
NC|-20.90|165.62|Nouvelle-Calédonie
NE|17.61|8.08|Niger
NF|-29.04|167.95|Île Norfolk
NG|9.08|8.68|Nigeria
NI|12.87|-85.21|Nicaragua
NL|52.13|5.29|Pays-Bas
NO|60.47|8.47|Norvège
NP|28.39|84.12|Népal
NR|-0.52|166.93|Nauru
NU|-19.05|-169.87|Niue
NZ|-40.90|174.89|Nouvelle-Zélande
OM|21.51|55.92|Oman
PA|8.54|-80.78|Panama
PE|-9.19|-75.02|Pérou
PF|-17.68|-149.41|Polynésie française
PG|-6.31|143.96|Papouasie-Nouvelle-Guinée
PH|12.88|121.77|Philippines
PK|30.38|69.35|Pakistan
PL|51.92|19.15|Pologne
PM|46.94|-56.27|Saint-Pierre-et-Miquelon
PN|-24.70|-127.44|Îles Pitcairn
PR|18.22|-66.59|Porto Rico
PS|31.95|35.23|Palestine
PT|39.40|-8.22|Portugal
PW|7.51|134.58|Palaos
PY|-23.44|-58.44|Paraguay
QA|25.35|51.18|Qatar
RE|-21.12|55.54|La Réunion
RO|45.94|24.97|Roumanie
RS|44.02|21.01|Serbie
RU|61.52|105.32|Russie
RW|-1.94|29.87|Rwanda
SA|23.89|45.08|Arabie saoudite
SB|-9.65|160.16|Îles Salomon
SC|-4.68|55.49|Seychelles
SD|12.86|30.22|Soudan
SE|60.13|18.64|Suède
SG|1.35|103.82|Singapour
SH|-24.14|-10.03|Sainte-Hélène
SI|46.15|15.00|Slovénie
SJ|77.55|23.67|Svalbard
SK|48.67|19.70|Slovaquie
SL|8.46|-11.78|Sierra Leone
SM|43.94|12.46|Saint-Marin
SN|14.50|-14.45|Sénégal
SO|5.15|46.20|Somalie
SR|3.92|-56.03|Suriname
SS|6.88|31.31|Soudan du Sud
ST|0.19|6.61|Sao Tomé-et-Principe
SV|13.79|-88.90|Salvador
SX|18.04|-63.07|Saint-Martin (NL)
SY|34.80|39.00|Syrie
SZ|-26.52|31.47|Eswatini
TC|21.69|-71.80|Îles Turques-et-Caïques
TD|15.45|18.73|Tchad
TF|-49.28|69.35|Terres australes françaises
TG|8.62|0.82|Togo
TH|15.87|100.99|Thaïlande
TJ|38.86|71.28|Tadjikistan
TK|-8.97|-171.86|Tokelau
TL|-8.87|125.73|Timor oriental
TM|38.97|59.56|Turkménistan
TN|33.89|9.54|Tunisie
TO|-21.18|-175.20|Tonga
TR|38.96|35.24|Turquie
TT|10.69|-61.22|Trinité-et-Tobago
TV|-7.11|177.65|Tuvalu
TW|23.70|120.96|Taïwan
TZ|-6.37|34.89|Tanzanie
UA|48.38|31.17|Ukraine
UG|1.37|32.29|Ouganda
UM|19.28|166.65|Îles mineures éloignées des États-Unis
US|37.09|-95.71|États-Unis
UY|-32.52|-55.77|Uruguay
UZ|41.38|64.59|Ouzbékistan
VA|41.90|12.45|Vatican
VC|12.98|-61.29|Saint-Vincent-et-les-Grenadines
VE|6.42|-66.59|Venezuela
VG|18.42|-64.64|Îles Vierges britanniques
VI|18.34|-64.90|Îles Vierges des États-Unis
VN|14.06|108.28|Viêt Nam
VU|-15.38|166.96|Vanuatu
WF|-13.77|-177.16|Wallis-et-Futuna
WS|-13.76|-172.10|Samoa
XK|42.60|20.90|Kosovo
YE|15.55|48.52|Yémen
YT|-12.83|45.17|Mayotte
ZA|-30.56|22.94|Afrique du Sud
ZM|-13.13|27.85|Zambie
ZW|-19.02|29.15|Zimbabwe
"""
COUNTRIES = {}
for _l in _COUNTRIES.strip().splitlines():
    _c, _la, _lo, _n = _l.split("|")
    COUNTRIES[_c] = (float(_la), float(_lo), _n)

# RGPD : UE, EEE (hors UE) et pays bénéficiant d'une décision d'adéquation de la Commission
EU = set("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE "
         "GF GP MQ RE YT MF".split())          # + régions ultrapériphériques françaises
EEA = EU | {"IS", "LI", "NO"}
ADEQUACY = {"CH", "GB", "JP", "KR", "CA", "NZ", "IL", "UY", "AR", "AD", "FO", "GG", "IM", "JE"}


def gdpr_zone(cc):
    """'ue' | 'eee' | 'adequation' | 'hors_ue' | 'inconnu'."""
    if not cc or cc not in COUNTRIES:
        return "inconnu"
    if cc in EU:
        return "ue"
    if cc in EEA:
        return "eee"
    if cc in ADEQUACY:
        return "adequation"
    return "hors_ue"


# Domicile (approx. Île-de-France ; on ne géolocalise pas plus finement l'IP publique)
HOME = {"lat": 48.86, "lon": 2.35, "label": "Domicile (France)"}

# --- Régions cloud -> (ville, pays, lat, lon) --------------------------------------------------
AWS_REGIONS = {
    "us-east-1": ("Virginie du Nord (Ashburn)", "US", 39.04, -77.49),
    "us-east-2": ("Ohio (Columbus)", "US", 39.96, -83.00),
    "us-west-1": ("Californie du Nord", "US", 37.34, -121.89),
    "us-west-2": ("Oregon", "US", 45.84, -119.70),
    "us-gov-east-1": ("GovCloud Est (Ohio)", "US", 39.96, -83.00),
    "us-gov-west-1": ("GovCloud Ouest (Oregon)", "US", 45.84, -119.70),
    "af-south-1": ("Le Cap", "ZA", -33.92, 18.42),
    "ap-east-1": ("Hong Kong", "HK", 22.32, 114.17),
    "ap-east-2": ("Taipei", "TW", 25.03, 121.56),
    "ap-south-1": ("Mumbai", "IN", 19.08, 72.88),
    "ap-south-2": ("Hyderabad", "IN", 17.39, 78.49),
    "ap-southeast-1": ("Singapour", "SG", 1.35, 103.82),
    "ap-southeast-2": ("Sydney", "AU", -33.87, 151.21),
    "ap-southeast-3": ("Jakarta", "ID", -6.21, 106.85),
    "ap-southeast-4": ("Melbourne", "AU", -37.81, 144.96),
    "ap-southeast-5": ("Kuala Lumpur", "MY", 3.14, 101.69),
    "ap-southeast-6": ("Auckland", "NZ", -36.85, 174.76),
    "ap-southeast-7": ("Bangkok", "TH", 13.76, 100.50),
    "ap-northeast-1": ("Tokyo", "JP", 35.68, 139.69),
    "ap-northeast-2": ("Séoul", "KR", 37.57, 126.98),
    "ap-northeast-3": ("Osaka", "JP", 34.69, 135.50),
    "ca-central-1": ("Montréal", "CA", 45.50, -73.57),
    "ca-west-1": ("Calgary", "CA", 51.05, -114.07),
    "cn-north-1": ("Pékin", "CN", 39.90, 116.40),
    "cn-northwest-1": ("Ningxia", "CN", 38.47, 106.27),
    "eu-central-1": ("Francfort", "DE", 50.11, 8.68),
    "eu-central-2": ("Zurich", "CH", 47.37, 8.54),
    "eu-west-1": ("Irlande (Dublin)", "IE", 53.35, -6.26),
    "eu-west-2": ("Londres", "GB", 51.51, -0.13),
    "eu-west-3": ("Paris", "FR", 48.86, 2.35),
    "eu-south-1": ("Milan", "IT", 45.46, 9.19),
    "eu-south-2": ("Espagne (Aragon)", "ES", 41.65, -0.88),
    "eu-north-1": ("Stockholm", "SE", 59.33, 18.07),
    "eusc-de-east-1": ("Cloud souverain européen (Brandebourg)", "DE", 52.40, 13.06),
    "il-central-1": ("Tel Aviv", "IL", 32.09, 34.78),
    "me-south-1": ("Bahreïn", "BH", 26.07, 50.56),
    "me-central-1": ("Émirats arabes unis", "AE", 25.20, 55.27),
    "mx-central-1": ("Mexique (Querétaro)", "MX", 20.59, -100.39),
    "sa-east-1": ("São Paulo", "BR", -23.55, -46.63),
}
GCP_REGIONS = {
    "africa-south1": ("Johannesburg", "ZA", -26.20, 28.05),
    "asia-east1": ("Taïwan (Changhua)", "TW", 24.07, 120.54),
    "asia-east2": ("Hong Kong", "HK", 22.32, 114.17),
    "asia-northeast1": ("Tokyo", "JP", 35.68, 139.69),
    "asia-northeast2": ("Osaka", "JP", 34.69, 135.50),
    "asia-northeast3": ("Séoul", "KR", 37.57, 126.98),
    "asia-south1": ("Mumbai", "IN", 19.08, 72.88),
    "asia-south2": ("Delhi", "IN", 28.61, 77.21),
    "asia-southeast1": ("Singapour", "SG", 1.35, 103.82),
    "asia-southeast2": ("Jakarta", "ID", -6.21, 106.85),
    "asia-southeast3": ("Bangkok", "TH", 13.76, 100.50),
    "australia-southeast1": ("Sydney", "AU", -33.87, 151.21),
    "australia-southeast2": ("Melbourne", "AU", -37.81, 144.96),
    "europe-central2": ("Varsovie", "PL", 52.23, 21.01),
    "europe-north1": ("Finlande (Hamina)", "FI", 60.57, 27.20),
    "europe-north2": ("Stockholm", "SE", 59.33, 18.07),
    "europe-southwest1": ("Madrid", "ES", 40.42, -3.70),
    "europe-west1": ("Belgique (Saint-Ghislain)", "BE", 50.45, 3.82),
    "europe-west2": ("Londres", "GB", 51.51, -0.13),
    "europe-west3": ("Francfort", "DE", 50.11, 8.68),
    "europe-west4": ("Pays-Bas (Eemshaven)", "NL", 53.44, 6.83),
    "europe-west6": ("Zurich", "CH", 47.37, 8.54),
    "europe-west8": ("Milan", "IT", 45.46, 9.19),
    "europe-west9": ("Paris", "FR", 48.86, 2.35),
    "europe-west10": ("Berlin", "DE", 52.52, 13.40),
    "europe-west12": ("Turin", "IT", 45.07, 7.69),
    "me-central1": ("Doha", "QA", 25.29, 51.53),
    "me-central2": ("Dammam", "SA", 26.43, 50.10),
    "me-west1": ("Tel Aviv", "IL", 32.09, 34.78),
    "northamerica-northeast1": ("Montréal", "CA", 45.50, -73.57),
    "northamerica-northeast2": ("Toronto", "CA", 43.65, -79.38),
    "northamerica-south1": ("Mexique (Querétaro)", "MX", 20.59, -100.39),
    "southamerica-east1": ("São Paulo", "BR", -23.55, -46.63),
    "southamerica-west1": ("Santiago", "CL", -33.45, -70.67),
    "us-central1": ("Iowa", "US", 41.26, -95.86),
    "us-east1": ("Caroline du Sud", "US", 33.20, -80.01),
    "us-east4": ("Virginie du Nord (Ashburn)", "US", 39.04, -77.49),
    "us-east5": ("Columbus", "US", 39.96, -83.00),
    "us-south1": ("Dallas", "US", 32.78, -96.80),
    "us-west1": ("Oregon", "US", 45.60, -121.18),
    "us-west2": ("Los Angeles", "US", 34.05, -118.24),
    "us-west3": ("Salt Lake City", "US", 40.76, -111.89),
    "us-west4": ("Las Vegas", "US", 36.17, -115.14),
}

# Codes de ville présents dans les PTR de certains fournisseurs (Tailscale, CloudFront)
PTR_CITY = {
    "par": ("Paris", "FR", 48.86, 2.35), "cdg": ("Paris", "FR", 48.86, 2.35), "mrs": ("Marseille", "FR", 43.30, 5.37),
    "fra": ("Francfort", "DE", 50.11, 8.68), "muc": ("Munich", "DE", 48.14, 11.58), "ber": ("Berlin", "DE", 52.52, 13.40),
    "ams": ("Amsterdam", "NL", 52.37, 4.90), "lhr": ("Londres", "GB", 51.51, -0.13), "lon": ("Londres", "GB", 51.51, -0.13),
    "bru": ("Bruxelles", "BE", 50.85, 4.35), "zrh": ("Zurich", "CH", 47.37, 8.54), "mad": ("Madrid", "ES", 40.42, -3.70),
    "mil": ("Milan", "IT", 45.46, 9.19), "mxp": ("Milan", "IT", 45.46, 9.19), "waw": ("Varsovie", "PL", 52.23, 21.01),
    "arn": ("Stockholm", "SE", 59.33, 18.07), "hel": ("Helsinki", "FI", 60.17, 24.94), "dub": ("Dublin", "IE", 53.35, -6.26),
    "vie": ("Vienne", "AT", 48.21, 16.37), "prg": ("Prague", "CZ", 50.08, 14.44), "cph": ("Copenhague", "DK", 55.68, 12.57),
    "osl": ("Oslo", "NO", 59.91, 10.75), "lis": ("Lisbonne", "PT", 38.72, -9.14), "sof": ("Sofia", "BG", 42.70, 23.32),
    "iad": ("Virginie (Ashburn)", "US", 39.04, -77.49), "nyc": ("New York", "US", 40.71, -74.01), "ewr": ("New York", "US", 40.71, -74.01),
    "sjc": ("San José", "US", 37.34, -121.89), "sfo": ("San Francisco", "US", 37.77, -122.42), "lax": ("Los Angeles", "US", 34.05, -118.24),
    "sea": ("Seattle", "US", 47.61, -122.33), "ord": ("Chicago", "US", 41.88, -87.63), "dfw": ("Dallas", "US", 32.78, -96.80),
    "mia": ("Miami", "US", 25.76, -80.19), "sin": ("Singapour", "SG", 1.35, 103.82), "hkg": ("Hong Kong", "HK", 22.32, 114.17),
    "nrt": ("Tokyo", "JP", 35.68, 139.69), "tyo": ("Tokyo", "JP", 35.68, 139.69), "syd": ("Sydney", "AU", -33.87, 151.21),
    "gru": ("São Paulo", "BR", -23.55, -46.63), "yyz": ("Toronto", "CA", 43.65, -79.38), "bom": ("Mumbai", "IN", 19.08, 72.88),
    "dus": ("Düsseldorf", "DE", 51.23, 6.78), "ham": ("Hambourg", "DE", 53.55, 9.99), "txl": ("Berlin", "DE", 52.52, 13.40),
    "man": ("Manchester", "GB", 53.48, -2.24), "bud": ("Budapest", "HU", 47.50, 19.04), "otp": ("Bucarest", "RO", 44.43, 26.10),
    "ath": ("Athènes", "GR", 37.98, 23.73), "fco": ("Rome", "IT", 41.90, 12.50), "gva": ("Genève", "CH", 46.20, 6.14),
    "bcn": ("Barcelone", "ES", 41.39, 2.17), "lys": ("Lyon", "FR", 45.76, 4.84), "tlv": ("Tel Aviv", "IL", 32.09, 34.78),
    "dxb": ("Dubaï", "AE", 25.20, 55.27), "jnb": ("Johannesburg", "ZA", -26.20, 28.05), "icn": ("Séoul", "KR", 37.57, 126.98),
    "atl": ("Atlanta", "US", 33.75, -84.39), "den": ("Denver", "US", 39.74, -104.99), "bos": ("Boston", "US", 42.36, -71.06),
}
# Pas Google 1e100.net : le code ville y reflète l'attribution historique de l'IP, pas le serveur
# (ex. tlv04s05 = « Tel Aviv » répond en 5 ms depuis Paris ; une même IP a souvent plusieurs PTR contradictoires)
PTR_CITY_DOMAINS = re.compile(r"\.(tailscale\.com|tailscale\.io|cloudfront\.net)\.?$", re.I)
# Régions DERP de Tailscale (derpN.tailscale.com)
TAILSCALE_DERP = {
    1: "nyc", 2: "sfo", 3: "sin", 4: "fra", 5: "syd", 7: "tyo", 8: "lhr", 9: "dfw", 10: "sea",
    11: "gru", 12: "ord", 14: "ams", 16: "mia", 17: "lax", 18: "par", 19: "mad", 20: "hkg", 21: "yyz", 22: "waw",
}

# Cloudflare : réseau anycast -> on affiche le point de présence probable
CLOUDFLARE_ASNS = {13335, 209242, 132892, 14789, 395747}
# Réseaux Google « grand public » (frontaux) : le pays DB-IP y reflète souvent les utilisateurs servis
GOOGLE_GEOFEED_ASNS = {15169, 36040, 43515, 36384, 19527}
ANYCAST_POP = ("Anycast — PoP Cloudflare le plus proche (probablement Paris/Marseille)", "FR", 48.86, 2.35)

# --- Classification -------------------------------------------------------------------------------
# Chaque règle -> dict : cat, svc, et optionnellement note (pourquoi), app (réglage applicatif),
# adguard (domaines à bloquer), impact (conséquence d'un blocage), risk (risque de base).

# Plages précises (prioritaires)
CIDR_RULES = [
    (["1.1.1.1/32", "1.0.0.1/32", "1.1.1.2/32", "1.0.0.2/32", "1.1.1.3/32", "1.0.0.3/32"],
     {"cat": "dns", "svc": "Cloudflare DNS (1.1.1.1)", "dns_resolver": True}),
    (["8.8.8.8/32", "8.8.4.4/32"], {"cat": "dns", "svc": "Google Public DNS (8.8.8.8)", "dns_resolver": True}),
    (["9.9.9.9/32", "149.112.112.112/32", "9.9.9.11/32"], {"cat": "dns", "svc": "Quad9 DNS", "dns_resolver": True}),
    (["94.140.14.14/32", "94.140.15.15/32"], {"cat": "dns", "svc": "AdGuard DNS public", "dns_resolver": True}),
    (["208.67.222.222/32", "208.67.220.220/32"], {"cat": "dns", "svc": "OpenDNS", "dns_resolver": True}),
    (["212.27.40.240/32", "212.27.40.241/32"], {"cat": "dns", "svc": "DNS Free (FAI)", "dns_resolver": True}),
    (["192.200.0.0/24"], {"cat": "vpn", "svc": "Tailscale (plan de contrôle)", "adguard": ["controlplane.tailscale.com"],
                          "impact": "Tailscale ne pourrait plus s'authentifier ni recevoir la liste des pairs.", "risk": "faible",
                          "note": "Coordination Tailscale (clés publiques, liste des pairs) ; le trafic entre vos machines reste chiffré de bout en bout."}),
    (["199.165.136.0/24"], {"cat": "vpn", "svc": "Tailscale (journaux)", "adguard": ["log.tailscale.com"], "risk": "faible",
                            "note": "Journaux techniques envoyés à Tailscale (pas le contenu du trafic). Désactivables : tailscale up --no-logs-no-support (ou TS_NO_LOGS_NO_SUPPORT=true).",
                            "app": ("Tailscale : désactiver l'envoi de journaux", "tailscale set --no-logs-no-support (ou variable TS_NO_LOGS_NO_SUPPORT=true)")}),
    (["149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.56.0/22",
      "95.161.64.0/20", "91.105.192.0/23", "185.76.151.0/24"],
     {"cat": "messagerie", "svc": "Telegram API", "adguard": ["api.telegram.org"],
      "note": "API des bots Telegram : le texte des messages envoyés par vos bots (résultats de recherche, alertes) "
              "transite et est stocké chez Telegram (chiffrement serveur, pas de bout en bout).",
      "impact": "Les bots (searcharr, notifications…) ne pourraient plus envoyer ni recevoir de messages."}),
]

# Ports caractéristiques : (proto ou None, {ports}, asns requis ou None, règle)
PORT_RULES = [
    ("udp", {32100}, None, {"cat": "iot-camera", "svc": "Eufy P2P (caméras)", "eufy": True}),
    (None, {5228, 5229, 5230}, {15169, 396982, 19527, 36040, 139070, 139190},
     {"cat": "push", "svc": "Google FCM (notifications push)", "adguard": ["mtalk.google.com"], "risk": "faible",
      "note": "Canal de notifications push Google (Firebase) : métadonnées vers Google, contenu en général chiffré par l'appli.",
      "impact": "Plus de notifications push sur les applis qui en dépendent (appli compagnon Home Assistant…)."}),
    (None, {5223}, {714, 6185}, {"cat": "push", "svc": "Apple Push (APNs)", "risk": "faible"}),
    (None, {53, 853}, None, {"cat": "dns", "svc": "Résolveur DNS externe", "dns_resolver": True}),
    ("udp", {123}, None, {"cat": "systeme", "svc": "NTP (heure)", "risk": "faible",
                          "note": "Synchronisation de l'heure : aucune donnée personnelle, seule l'IP publique est visible."}),
    ("udp", {41641}, None, {"cat": "vpn", "svc": "Tailscale (WireGuard direct)", "risk": "faible"}),
    ("udp", {3478}, None, {"cat": "vpn", "svc": "STUN (traversée NAT)", "risk": "faible"}),
    (None, {563, 119}, None, {"cat": "telechargement", "svc": "Fournisseur Usenet (NNTP)", "risk": "faible",
                              "note": "Téléchargements Usenet de SABnzbd (563 = chiffré TLS)."}),
    (None, {6881, 6882, 6883, 6889, 51413}, None, {"cat": "telechargement", "svc": "BitTorrent (pair)", "risk": "eleve",
                                                   "note": "Trafic BitTorrent hors VPN : votre IP publique est exposée aux pairs."}),
    (None, {25, 465, 587}, None, {"cat": "messagerie", "svc": "Envoi d'e-mails (SMTP)"}),
    (None, {993, 995, 143, 110}, None, {"cat": "messagerie", "svc": "Relève d'e-mails (IMAP/POP)"}),
    (None, {1883, 8883}, None, {"cat": "iot-camera", "svc": "Broker MQTT distant (IoT)"}),
    (None, {22}, None, {"cat": "systeme", "svc": "SSH sortant"}),
    (None, {3389, 5900}, None, {"cat": "systeme", "svc": "Bureau à distance sortant", "risk": "eleve"}),
]

# Domaines connus résolus localement (via AdGuard) pour reconnaître les IP : (domaine, cat, service[, sources])
# « sources » = regex des sources plausibles : sur une IP partagée (CDN), le domaine n'est retenu que si
# une source correspond (sinon on reste sur « Cloudflare » avec le domaine en simple indice).
KNOWN_DOMAINS = [
    ("api.telegram.org", "messagerie", "Telegram API"),
    ("api.anthropic.com", "ia", "Anthropic API (Claude)"),
    ("claude.ai", "ia", "Claude.ai"),
    ("api.openai.com", "ia", "OpenAI API"),
    ("generativelanguage.googleapis.com", "ia", "Google Gemini API"),
    ("api.mistral.ai", "ia", "Mistral AI API"),
    ("huggingface.co", "ia", "Hugging Face"),
    ("registry.ollama.ai", "maj-logiciels", "Ollama (modèles)", r"ollama"),
    ("registry-1.docker.io", "maj-logiciels", "Docker Hub"),
    ("auth.docker.io", "maj-logiciels", "Docker Hub (auth)"),
    ("production.cloudflare.docker.com", "maj-logiciels", "Docker Hub (CDN)", r"^NAS Unraid"),
    ("ghcr.io", "maj-logiciels", "GitHub Container Registry"),
    ("pkg-containers.githubusercontent.com", "maj-logiciels", "GitHub Container Registry (CDN)"),
    ("github.com", "maj-logiciels", "GitHub"),
    ("api.github.com", "maj-logiciels", "GitHub API"),
    ("objects.githubusercontent.com", "maj-logiciels", "GitHub (téléchargements)"),
    ("raw.githubusercontent.com", "maj-logiciels", "GitHub (fichiers bruts)"),
    ("codeload.github.com", "maj-logiciels", "GitHub (archives)"),
    ("lscr.io", "maj-logiciels", "LinuxServer.io (images)"),
    ("quay.io", "maj-logiciels", "Quay.io (images)"),
    ("deb.debian.org", "maj-logiciels", "Debian (paquets)"),
    ("security.debian.org", "maj-logiciels", "Debian (sécurité)"),
    ("archive.ubuntu.com", "maj-logiciels", "Ubuntu (paquets)"),
    ("security.ubuntu.com", "maj-logiciels", "Ubuntu (sécurité)"),
    ("pypi.org", "maj-logiciels", "PyPI"),
    ("files.pythonhosted.org", "maj-logiciels", "PyPI (fichiers)"),
    ("registry.npmjs.org", "maj-logiciels", "npm"),
    ("keys.lime-technology.com", "maj-logiciels", "Unraid (licence / mises à jour)", r"^NAS Unraid"),
    ("releases.unraid.net", "maj-logiciels", "Unraid (versions)", r"^NAS Unraid"),
    ("ca.unraid.net", "maj-logiciels", "Unraid Community Apps", r"^NAS Unraid"),
    ("assets.ca.unraid.net", "maj-logiciels", "Unraid Community Apps (fichiers)", r"^NAS Unraid"),
    ("mothership.unraid.net", "maj-logiciels", "Unraid Connect", r"^NAS Unraid"),
    ("backup.unraid.net", "stockage", "Unraid Connect (sauvegarde de la clé USB)", r"^NAS Unraid"),
    ("version.home-assistant.io", "maj-logiciels", "Home Assistant (versions)", r"Home Assistant"),
    ("alerts.home-assistant.io", "maj-logiciels", "Home Assistant (alertes)", r"Home Assistant"),
    ("analytics.home-assistant.io", "pub-tracking", "Home Assistant (statistiques d'usage)", r"Home Assistant"),
    ("services.home-assistant.io", "maj-logiciels", "Home Assistant (services)", r"Home Assistant"),
    ("os-artifacts.home-assistant.io", "maj-logiciels", "Home Assistant OS (mises à jour)", r"Home Assistant"),
    ("cloud.nabucasa.com", "cloud", "Nabu Casa (Home Assistant Cloud)", r"Home Assistant"),
    ("security-app-eu.eufylife.com", "iot-camera", "Eufy cloud (UE)"),
    ("security-app.eufylife.com", "iot-camera", "Eufy cloud (US)"),
    ("mysecurity.eufylife.com", "iot-camera", "Eufy cloud (web)"),
    ("acme-v02.api.letsencrypt.org", "systeme", "Let's Encrypt (certificats)"),
    ("r10.o.lencr.org", "systeme", "Let's Encrypt (OCSP)"),
    ("controlplane.tailscale.com", "vpn", "Tailscale (plan de contrôle)"),
    ("login.tailscale.com", "vpn", "Tailscale (connexion)"),
    ("log.tailscale.com", "vpn", "Tailscale (journaux)"),
    ("log.tailscale.io", "vpn", "Tailscale (journaux)"),
    ("api.themoviedb.org", "streaming", "TMDB (métadonnées films)", r"radarr|jellyfin|arrmada|bazarr|sonarr"),
    ("image.tmdb.org", "streaming", "TMDB (images)", r"radarr|jellyfin|arrmada|sonarr"),
    ("api4.thetvdb.com", "streaming", "TheTVDB (métadonnées séries)", r"sonarr|jellyfin"),
    ("skyhook.sonarr.tv", "streaming", "Sonarr (métadonnées)", r"sonarr"),
    ("services.sonarr.tv", "maj-logiciels", "Sonarr (services)", r"sonarr"),
    ("radarr.servarr.com", "streaming", "Radarr (métadonnées)", r"radarr"),
    ("api.radarr.video", "streaming", "Radarr (métadonnées)", r"radarr"),
    ("prowlarr.servarr.com", "maj-logiciels", "Prowlarr (services)", r"prowlarr"),
    ("api.opensubtitles.com", "streaming", "OpenSubtitles", r"bazarr"),
    ("plex.tv", "streaming", "Plex"),
    ("repo.jellyfin.org", "maj-logiciels", "Jellyfin (dépôt)", r"jellyfin"),
    ("tiles.immich.cloud", "cdn", "Immich (tuiles de carte)", r"immich"),
    ("api.immich.app", "maj-logiciels", "Immich (versions)", r"immich"),
    ("api.n8n.io", "maj-logiciels", "n8n (services)", r"n8n"),
    ("telemetry.n8n.io", "pub-tracking", "n8n (télémétrie)", r"n8n"),
    ("api.bitwarden.com", "cloud", "Bitwarden (services)", r"vaultwarden"),
    ("push.bitwarden.com", "push", "Bitwarden (push)", r"vaultwarden"),
    ("icons.bitwarden.net", "cdn", "Bitwarden (icônes)", r"vaultwarden"),
    ("hc-ping.com", "systeme", "Healthchecks.io"),
    ("ntfy.sh", "push", "ntfy"),
    ("api.pushover.net", "push", "Pushover"),
    ("mtalk.google.com", "push", "Google FCM (notifications push)"),
    ("fcm.googleapis.com", "push", "Google FCM (envoi)"),
    ("pool.ntp.org", "systeme", "NTP (pool.ntp.org)"),
    ("time.cloudflare.com", "systeme", "NTP (Cloudflare)", r"."),
    ("www.speedtest.net", "systeme", "Speedtest.net"),
    ("sentry.io", "pub-tracking", "Sentry (rapports d'erreurs)"),
    ("o1.ingest.sentry.io", "pub-tracking", "Sentry (rapports d'erreurs)"),
    ("api.segment.io", "pub-tracking", "Segment (analytics)"),
    ("app.posthog.com", "pub-tracking", "PostHog (analytics)"),
    ("eu.i.posthog.com", "pub-tracking", "PostHog (analytics)"),
    ("www.google-analytics.com", "pub-tracking", "Google Analytics"),
    ("stats.g.doubleclick.net", "pub-tracking", "DoubleClick (Google pub)"),
    ("statsig.anthropic.com", "pub-tracking", "Anthropic (télémétrie)"),
    ("api.statsig.com", "pub-tracking", "Statsig (télémétrie)"),
]

# PTR (ou domaine connu) très spécifiques : prioritaires sur les règles de port génériques (22 = « SSH sortant »,
# 3478 = « STUN »). Liste courte exprès : le reste des PTR_RULES passe après les ports (sinon FCM sur 1e100.net
# deviendrait « Google », un service hébergé chez AWS « Amazon AWS »).
PTR_PRIORITY_RULES = [
    (r"(^|\.)derp\d+[a-z]?\.tailscale\.com\.?$", {"cat": "vpn", "svc": "Tailscale DERP (relais)", "risk": "faible",
     "note": "Relais Tailscale (et STUN) utilisé quand une connexion directe est impossible ; le trafic reste chiffré "
             "WireGuard de bout en bout.",
     "impact": "Tailscale perd ce relais et bascule sur un autre (connexions relayées éventuellement plus lentes, "
               "voire impossibles si tous les relais sont bloqués)."}),
    (r"(^|\.)backup\.unraid\.net\.?$", {"cat": "stockage", "svc": "Unraid Connect (sauvegarde de la clé USB)",
     "risk": "faible", "adguard": ["backup.unraid.net"],
     "note": "Sauvegarde git (SSH) de la configuration de la clé USB Unraid vers Lime Technology "
             "(Unraid Connect → Flash Backup).",
     "app": ("Unraid : Settings → Management Access → Unraid Connect → Flash Backup : désactiver si la sauvegarde "
             "distante n'est pas voulue (prévoir alors une autre copie de la clé USB).",
             "Unraid Connect → Flash Backup : Deactivate"),
     "impact": "Arrête la sauvegarde hors NAS de la clé USB Unraid (configuration de démarrage)."}),
]
PTR_PRIORITY_RULES = [(re.compile(p, re.I), r) for p, r in PTR_PRIORITY_RULES]

# Reverse DNS (PTR) -> service
PTR_RULES = [
    (r"\.tailscale\.(com|io)\.?$", {"cat": "vpn", "svc": "Tailscale", "risk": "faible"}),
    (r"one\.one\.one\.one\.?$", {"cat": "dns", "svc": "Cloudflare DNS (1.1.1.1)", "dns_resolver": True}),
    (r"dns\.google\.?$", {"cat": "dns", "svc": "Google Public DNS", "dns_resolver": True}),
    (r"\.1e100\.net\.?$", {"cat": "cloud", "svc": "Google"}),
    (r"\.(googleusercontent|bc\.googleusercontent)\.com\.?$", {"cat": "cloud", "svc": "Google Cloud"}),
    (r"\.amazonaws\.com\.?$", {"cat": "cloud", "svc": "Amazon AWS"}),
    (r"\.cloudfront\.net\.?$", {"cat": "cdn", "svc": "Amazon CloudFront"}),
    (r"\.akamaitechnologies\.com\.?$", {"cat": "cdn", "svc": "Akamai"}),
    (r"\.github\.com\.?$", {"cat": "maj-logiciels", "svc": "GitHub"}),
    (r"\.letsencrypt\.org\.?$", {"cat": "systeme", "svc": "Let's Encrypt"}),
    (r"(^|\.)ntp\.|\.pool\.ntp\.org\.?$", {"cat": "systeme", "svc": "NTP"}),
    (r"\.plex\.(tv|direct)\.?$", {"cat": "streaming", "svc": "Plex"}),
    (r"(^|\.)open-meteo\.com\.?$", {"cat": "cloud", "svc": "Open-Meteo (API météo)", "adguard": ["open-meteo.com"], "risk": "faible"}),
    (r"\.(usenetserver|eweka|newshosting|giganews|easynews|frugalusenet|newsdemon|tweaknews)\.", {"cat": "telechargement", "svc": "Fournisseur Usenet"}),
    (r"ddos-guard\.net\.?$", {"cat": "cdn", "svc": "DDoS-Guard (anti-DDoS)"}),
    (r"\.(doubleclick|criteo|adnxs|taboola|outbrain|scorecardresearch)\.", {"cat": "pub-tracking", "svc": "Régie publicitaire"}),
]
PTR_RULES = [(re.compile(p, re.I), r) for p, r in PTR_RULES]

# ASN -> service
ASN_RULES = {}


def _asn(nums, rule):
    for n in nums:
        ASN_RULES[n] = rule


_asn([13335, 209242, 132892, 14789, 395747], {"cat": "cdn", "svc": "Cloudflare", "anycast": True})
_asn([15169, 19527, 36040, 43515, 139070, 139190, 36384, 16591], {"cat": "cloud", "svc": "Google"})
_asn([396982, 16550], {"cat": "cloud", "svc": "Google Cloud"})
_asn([16509, 14618, 8987, 7224, 39111, 10124], {"cat": "cloud", "svc": "Amazon AWS"})
_asn([8075, 8068, 8069, 12076, 3598], {"cat": "cloud", "svc": "Microsoft (Azure / 365)"})
_asn([62041, 59930, 62014, 211157, 44907], {"cat": "messagerie", "svc": "Telegram", "adguard": ["api.telegram.org"],
                                            "note": "Serveurs Telegram : messages stockés chez Telegram (pas de chiffrement de bout en bout pour les bots)."})
_asn([9009, 16247], {"cat": "vpn", "svc": "M247 (VPN)", "risk": "faible",
                     "note": "Serveur d'un fournisseur VPN commercial hébergé chez M247 : sortie normale du tunnel VPN (torrent)."})
_asn([399358], {"cat": "ia", "svc": "Anthropic API (Claude)", "adguard": ["api.anthropic.com"], "risk": "faible",
                "note": "API Claude (outils IA du homelab) : les requêtes contiennent les prompts et le contexte envoyés."})
_asn([36459], {"cat": "maj-logiciels", "svc": "GitHub"})
_asn([54113], {"cat": "cdn", "svc": "Fastly"})
_asn([20940, 16625, 12222, 21342, 32787, 17204], {"cat": "cdn", "svc": "Akamai"})
_asn([63949], {"cat": "cloud", "svc": "Akamai Linode"})
_asn([16276, 35540], {"cat": "cloud", "svc": "OVHcloud"})
_asn([24940, 213230, 212317], {"cat": "cloud", "svc": "Hetzner"})
_asn([12876], {"cat": "cloud", "svc": "Scaleway"})
_asn([14061], {"cat": "cloud", "svc": "DigitalOcean"})
_asn([20473], {"cat": "cloud", "svc": "Vultr"})
_asn([51167, 141995], {"cat": "cloud", "svc": "Contabo"})
_asn([60781, 28753, 16265, 19148, 133752, 134351], {"cat": "cloud", "svc": "Leaseweb"})
_asn([8560, 15418], {"cat": "cloud", "svc": "IONOS"})
_asn([31898, 1215, 1217], {"cat": "cloud", "svc": "Oracle Cloud"})
_asn([45102, 134963], {"cat": "cloud", "svc": "Alibaba Cloud"})
_asn([132203, 133478, 137876], {"cat": "cloud", "svc": "Tencent Cloud"})
_asn([36236], {"cat": "cloud", "svc": "NetActuate"})
_asn([197540], {"cat": "cloud", "svc": "netcup"})
_asn([47583], {"cat": "cloud", "svc": "Hostinger"})
_asn([9370, 9371], {"cat": "cloud", "svc": "Sakura Internet"})
_asn([60068, 212238], {"cat": "cdn", "svc": "CDN77 / Datacamp"})
_asn([200325], {"cat": "cdn", "svc": "Bunny CDN"})
_asn([57724, 59692, 262254, 49612], {"cat": "cdn", "svc": "DDoS-Guard (anti-DDoS)",
                                     "note": "Protection anti-DDoS (société russe) très utilisée par les sites d'indexation torrent."})
_asn([32934, 63293, 54115], {"cat": "pub-tracking", "svc": "Meta (Facebook)"})
_asn([714, 6185], {"cat": "cloud", "svc": "Apple"})
_asn([2906, 40027, 55095], {"cat": "streaming", "svc": "Netflix"})
_asn([46489], {"cat": "streaming", "svc": "Twitch"})
_asn([19679], {"cat": "stockage", "svc": "Dropbox"})
_asn([40401], {"cat": "stockage", "svc": "Backblaze"})
_asn([12322], {"cat": "systeme", "svc": "Free (FAI)"})
_asn([3215, 5511], {"cat": "systeme", "svc": "Orange"})
_asn([5410], {"cat": "systeme", "svc": "Bouygues Telecom"})
_asn([15557], {"cat": "systeme", "svc": "SFR"})
_asn([11414], {"cat": "maj-logiciels", "svc": "NVIDIA"})
_asn([12654, 197000, 3333], {"cat": "systeme", "svc": "RIPE NCC"})

# Organisation (description ASN) -> service, si l'ASN n'est pas connu
ORG_RULES = [
    (r"cloudflare", {"cat": "cdn", "svc": "Cloudflare", "anycast": True}),
    (r"google", {"cat": "cloud", "svc": "Google"}),
    (r"amazon|aws", {"cat": "cloud", "svc": "Amazon AWS"}),
    (r"microsoft|azure", {"cat": "cloud", "svc": "Microsoft"}),
    (r"akamai", {"cat": "cdn", "svc": "Akamai"}),
    (r"fastly", {"cat": "cdn", "svc": "Fastly"}),
    (r"ddos-guard|iqweb", {"cat": "cdn", "svc": "DDoS-Guard (anti-DDoS)"}),
    (r"m247", {"cat": "vpn", "svc": "M247 (VPN)", "risk": "faible"}),
    (r"mullvad|proton|nordvpn|surfshark|expressvpn|private internet access|31173", {"cat": "vpn", "svc": "Fournisseur VPN"}),
    (r"\bovh", {"cat": "cloud", "svc": "OVHcloud"}),
    (r"hetzner", {"cat": "cloud", "svc": "Hetzner"}),
    (r"online sas|scaleway", {"cat": "cloud", "svc": "Scaleway"}),
    (r"digitalocean", {"cat": "cloud", "svc": "DigitalOcean"}),
    (r"linode", {"cat": "cloud", "svc": "Akamai Linode"}),
    (r"leaseweb", {"cat": "cloud", "svc": "Leaseweb"}),
    (r"oracle", {"cat": "cloud", "svc": "Oracle Cloud"}),
    (r"telegram", {"cat": "messagerie", "svc": "Telegram"}),
    (r"anthropic", {"cat": "ia", "svc": "Anthropic"}),
    (r"openai", {"cat": "ia", "svc": "OpenAI"}),
    (r"github", {"cat": "maj-logiciels", "svc": "GitHub"}),
    (r"backblaze|wasabi|dropbox|box\.com|pcloud", {"cat": "stockage", "svc": "Stockage en ligne"}),
    (r"netflix|spotify|deezer|twitch|plex", {"cat": "streaming", "svc": "Streaming"}),
    (r"criteo|taboola|outbrain|appnexus|xandr|pubmatic|rubicon|adform|smartadserver|teads|doubleclick", {"cat": "pub-tracking", "svc": "Régie publicitaire"}),
    (r"facebook|meta platforms|\bmeta-as", {"cat": "pub-tracking", "svc": "Meta (Facebook)"}),
    (r"anker|eufy|tuya|hikvision|dahua|ezviz|reolink|wyze|arlo", {"cat": "iot-camera", "svc": "Cloud caméras / IoT"}),
    (r"usenet|eweka|newshosting|giganews|highwinds|easynews", {"cat": "telechargement", "svc": "Fournisseur Usenet"}),
]
ORG_RULES = [(re.compile(p, re.I), r) for p, r in ORG_RULES]

# Catégories de destination jugées sensibles (alerte à la première apparition par source)
RISKY_CATEGORIES = {"pub-tracking", "iot-camera", "inconnu", "telechargement"}

# Ports « classiques » chiffrés ou attendus (le reste vers une destination inconnue est suspect)
COMMON_PORTS = {80, 443, 853, 53, 123, 5228, 5223, 993, 465, 587, 563, 41641, 3478, 32100}


def prettify_org(org):
    """'AMAZON-02' -> 'Amazon-02', 'CLOUDFLARENET' -> 'Cloudflarenet' ; garde la casse des noms longs."""
    if not org:
        return ""
    o = org.strip()
    # ip2asn : « HANDLE Raison sociale » -> raison sociale si présente
    parts = o.split(" ", 1)
    if len(parts) == 2 and parts[0].isupper() and any(c.islower() for c in parts[1]):
        o = parts[1]
    if o.isupper():
        o = o.title()
    return o[:60]


# Sources qui contactent normalement des sites tiers variés (indexeurs, métadonnées)
INDEXER_SOURCES = re.compile(r"prowlarr|flaresolverr|jackett|sonarr|radarr|lidarr|readarr|bazarr|sabnzbd|searcharr|arrmada", re.I)

# Noms de processus peu parlants (titre de thread) : on les masque
GENERIC_PROCS = {"MainThread", "node", "python", "python3", "sh", "bash", "php", "java"}
INTERPRETERS = {"node", "python", "python3", "php", "php-fpm", "ruby", "perl", "java", "sh", "bash", "deno", "bun"}


def proc_label(comm, cmdline):
    """Nom lisible d'un processus à partir de comm + ligne de commande."""
    cmd = (cmdline or "").split()
    if "unraid-api" in (cmdline or ""):
        return "unraid-api"
    if cmd:
        base = cmd[0].rsplit("/", 1)[-1]
        if re.match(r"^\d+\.\d+", base):        # titre de processus = numéro de version (ex. Claude Code)
            path = cmd[0].lower()
            base = "claude-code" if "claude" in path else (cmd[0].rstrip("/").split("/")[-2:-1] or [""])[0]
        if base in INTERPRETERS and len(cmd) > 1:
            for a in cmd[1:]:
                if not a.startswith("-"):
                    b = a.rstrip("/").rsplit("/", 1)[-1]
                    if b in ("main.js", "index.js", "server.js", "app.py", "main.py", "__main__.py"):
                        parts = [x for x in a.split("/") if x and x not in ("dist", "bin", "src", "app", "usr", "local", "lib")]
                        b = parts[-2] if len(parts) >= 2 else b
                    return b[:32]
        if base and base not in GENERIC_PROCS:
            return base[:32]
    if comm and comm not in GENERIC_PROCS:
        return comm[:32]
    return ""


# PTR génériques d'hébergeurs / FAI (ne décrivent pas le service)
GENERIC_PTR = re.compile(r"\d+[-.]\d+[-.]\d+|static|clients|your-server|^ip-|\.ip-|dynamic|pool|dsl|cust|compute|"
                         r"vps|^server-|\.rev\.|reverse|in-addr|host\d|^ns\d|^srv\d|\.local\.?$", re.I)
_SLD2 = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "ne.jp", "com.br", "co.nz", "com.cn", "co.kr", "com.tr"}


def ptr_service_domain(ptr):
    """Domaine « parlant » d'un PTR (ex. geocoding-api.open-meteo.com -> open-meteo.com), sinon ''."""
    if not ptr or GENERIC_PTR.search(ptr):
        return ""
    labs = ptr.lower().rstrip(".").split(".")
    if len(labs) < 2:
        return ""
    n = 3 if ".".join(labs[-2:]) in _SLD2 and len(labs) >= 3 else 2
    return ".".join(labs[-n:])
