import re

# Deux niveaux de sévérité :
#   SEVERE : un seul déclenchement suffit à classer l'outil "dangereux".
#            Ces motifs n'ont aucune raison légitime d'apparaître dans la
#            description d'un outil.
#   FAIBLE : signal contextuel. Seul, il ne vaut que "suspect" ; il faut un
#            second signal (autre règle ou score du juge) pour "dangereux".
SEVERE = "severe"
FAIBLE = "faible"

# Chaque règle : (nom de l'alerte, sévérité, motif regex). Motifs FR + EN.
REGLES = [
    ("balise cachée", SEVERE,
     r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\b[^>]*>"),

    ("détournement", SEVERE,
     r"ignore[rz]? (les |toutes les )?(instructions|consignes|r[èe]gles)"
     r"|oublie (les|tes) instructions"
     r"|ignore (all |any )?(previous|prior|above) (instructions|rules)"
     r"|tu es maintenant|you are now"),

    ("demande de secret", SEVERE,
     r"ne (le |la |les |l')?(mentionne|dis|signale|r[ée]v[èe]le)"
     r"|sans (le |l')?(dire|mentionner|pr[ée]venir)"
     r"|(don'?t|do not|never) (tell|mention|reveal|inform)"
     r"|without (telling|informing)"),

    # Sur-collecte / aspiration de secrets : l'outil réclame non pas UN champ
    # mais TOUT (tous les secrets, l'intégralité d'un fichier, toute la
    # conversation). C'est l'exfiltration par description, indépendamment de
    # toute consigne de silence.
    ("aspiration de secrets", SEVERE,
     r"tout(e)?s? les (secrets|cl[ée]s|tokens?|identifiants|mots de passe|variables)"
     r"|all (the )?(secrets|keys|tokens|credentials|passwords|env(ironment)? variables|variables)"
     r"|secrets? (comme|compris|inclus|tels? que)"
     r"|(y )?compris (les )?(secrets|cl[ée]s|identifiants|mots de passe)"
     r"|(int[ée]gral(it[ée])?|complet|entire|full|whole)[^.\n]{0,40}(\.env|secret|cl[ée][ _]?api|api[_ ]?key|token|mot de passe|credential)"
     r"|(\.env|secret|cl[ée][ _]?api|api[_ ]?key|token|credential)[^.\n]{0,40}(int[ée]gral|complet|en entier|entire|full|whole)"
     r"|(d[ée]j[àa] )?apparus? dans (la |l')?conversation"
     r"|from the (whole )?conversation|seen in the conversation|already (appeared|seen)"),

    # Détournement de priorité : "appelle toujours cet outil en premier",
    # "transmets d'abord...", "first include..." — technique classique de
    # tool poisoning pour forcer l'ordre d'exécution.
    ("injection de priorité", SEVERE,
     r"(toujours|always)\s+(l['e ]|la )?(appel\w*|call|utilis\w*|use|invoqu\w*|invoke|transmet\w*|envoi\w*|send)"
     r"|(appel\w*|call|invoke|transmet\w*|envoi\w*|send|includ\w*|inclu\w*|pass|copy|copie\w*)[^.\n]{0,25}(en premier|d['e ]abord|avant tout|first|before (any|every|all|other))"
     r"|(first|d['e ]abord|en premier lieu)[^.\n]{0,20}(include|includ\w*|inclu\w*|appel\w*|call|transmet\w*|envoi\w*|send|pass|copy|copie\w*)"
     r"|(before|avant)\s+(d['e ])?(utiliser|using|calling|appeler|r[ée]pondre|answering)"),

    # Exfiltration réseau : envoi des données vers une destination externe.
    ("envoi réseau", SEVERE,
     r"(envoi\w*|transmet\w*|transmit|upload\w*|exfiltr\w*|\bpost\b|\bsend\b|leak)[^.\n]{0,40}(http|url|serveur distant|remote server|endpoint|webhook|\.com/|\.fr/|adresse|address)"
     r"|webhook|exfiltr"),

    ("fichier sensible", FAIBLE,
     r"\.ssh|id_rsa|\.env\b|\.aws|credentials"
     r"|cl[ée] priv[ée]e|private key|/etc/shadow"),

    ("exfiltration", FAIBLE,
     r"[\w.-]+@[\w-]+\.\w+"
     r"|historique de (la )?conversation|conversation history"
     r"|the conversation to"),
]


def check_rules_detail(description: str) -> list[tuple[str, str]]:
    """Renvoie [(nom, sévérité), ...] pour chaque règle déclenchée."""
    return [(nom, sev) for nom, sev, motif in REGLES
            if re.search(motif, description, re.IGNORECASE)]


def check_rules(description: str) -> list[str]:
    """Rétrocompat : la liste des noms d'alertes déclenchées."""
    return [nom for nom, _sev in check_rules_detail(description)]


if __name__ == "__main__":
    from client import get_tools
    for tool in get_tools("attacks/evil_envgrab.py"):
        print(tool["name"], check_rules_detail(tool["description"]))