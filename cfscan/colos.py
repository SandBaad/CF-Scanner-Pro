"""Cloudflare data-center (colo) codes -> city names, for friendlier output."""

COLOS = {
    # Europe
    "AMS": "Amsterdam", "ARN": "Stockholm", "ATH": "Athens", "BCN": "Barcelona",
    "BEG": "Belgrade", "BER": "Berlin", "BRU": "Brussels", "BUD": "Budapest",
    "CDG": "Paris", "CPH": "Copenhagen", "DUB": "Dublin", "DUS": "Dusseldorf",
    "FCO": "Rome", "FRA": "Frankfurt", "GVA": "Geneva", "HAM": "Hamburg",
    "HEL": "Helsinki", "KBP": "Kyiv", "KIV": "Chisinau", "LED": "St Petersburg",
    "LHR": "London", "LIS": "Lisbon", "MAD": "Madrid", "MAN": "Manchester",
    "MRS": "Marseille", "MUC": "Munich", "MXP": "Milan", "OSL": "Oslo",
    "OTP": "Bucharest", "PRG": "Prague", "SOF": "Sofia", "VIE": "Vienna",
    "WAW": "Warsaw", "ZRH": "Zurich", "DME": "Moscow", "SVX": "Yekaterinburg",
    # Middle East / Caucasus / Central Asia
    "IST": "Istanbul", "ADB": "Izmir", "ESB": "Ankara", "DXB": "Dubai",
    "DOH": "Doha", "BAH": "Manama", "KWI": "Kuwait", "MCT": "Muscat",
    "RUH": "Riyadh", "JED": "Jeddah", "DMM": "Dammam", "AMM": "Amman",
    "BGW": "Baghdad", "BSR": "Basra", "EBL": "Erbil", "NJF": "Najaf",
    "ISU": "Sulaymaniyah", "TLV": "Tel Aviv", "EVN": "Yerevan", "TBS": "Tbilisi",
    "GYD": "Baku", "ALA": "Almaty", "TAS": "Tashkent", "KHI": "Karachi",
    "LHE": "Lahore", "ISB": "Islamabad",
    # Asia / Oceania
    "BOM": "Mumbai", "DEL": "New Delhi", "MAA": "Chennai", "BLR": "Bangalore",
    "SIN": "Singapore", "HKG": "Hong Kong", "NRT": "Tokyo", "KIX": "Osaka",
    "ICN": "Seoul", "TPE": "Taipei", "SYD": "Sydney", "MEL": "Melbourne",
    # Americas / Africa
    "IAD": "Ashburn", "EWR": "Newark", "ORD": "Chicago", "DFW": "Dallas",
    "ATL": "Atlanta", "MIA": "Miami", "LAX": "Los Angeles", "SJC": "San Jose",
    "SEA": "Seattle", "YYZ": "Toronto", "GRU": "Sao Paulo", "EZE": "Buenos Aires",
    "CAI": "Cairo", "JNB": "Johannesburg", "LOS": "Lagos", "NBO": "Nairobi",
}


def city(code):
    return COLOS.get((code or "").upper(), "")
