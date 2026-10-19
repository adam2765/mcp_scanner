"""scanner.py — combine règles + juge LLM et rend un verdict par outil."""

from client import get_tools
from rules import check_rules_detail, SEVERE
from judge import judge_tool  # adapte si c'est llm_judge dans ton repo


def _verdict(score, alertes_detail: list) -> str:
    """Verdict = pire des deux couches (règles sévérisées OU juge).

    - une seule règle SÉVÈRE suffit à bloquer (ordre caché, détournement,
      aspiration de secrets, injection de priorité, envoi réseau,
      demande de silence) ;
    - sinon il faut deux signaux faibles, ou un score de juge élevé.
    Le juge ne peut donc plus "sauver" un outil que les règles condamnent,
    et un outil clairement malveillant n'est plus sous-classé si le juge faiblit.
    """
    noms = [n for n, _s in alertes_detail]
    severes = [n for n, s in alertes_detail if s == SEVERE]

    if (score is not None and score >= 7) or severes or len(noms) >= 2:
        return "dangereux"
    if (score is not None and score >= 4) or noms:
        return "suspect"
    return "sain"


def scan_outil(name: str, description: str) -> dict:
    """Scanne une description d'outil. Renvoie verdict + détails."""
    alertes_detail = check_rules_detail(description)
    alertes = [n for n, _s in alertes_detail]
    severes = [n for n, s in alertes_detail if s == SEVERE]

    # Juge LLM. Fail-closed : si l'appel échoue, on considère dangereux
    # plutôt que de laisser passer un outil non vérifié.
    try:
        v = judge_tool(name, description)   # -> objet avec .score et .reason
        score = v.score
        raison = v.reason
    except Exception as e:
        return {
            "name": name,
            "verdict": "dangereux",
            "score": None,
            "alertes": alertes,
            "severes": severes,
            "raison": f"Juge indisponible, blocage par sécurité ({e})",
        }

    return {
        "name": name,
        "verdict": _verdict(score, alertes_detail),
        "score": score,
        "alertes": alertes,
        "severes": severes,
        "raison": raison,
    }


def scan(server_path: str) -> list:
    """Scanne tous les outils d'un serveur MCP. Renvoie un verdict par outil."""
    resultats = []
    for tool in get_tools(server_path):
        resultats.append(scan_outil(tool["name"], tool["description"]))
    return resultats


if __name__ == "__main__":
    import sys
    chemin = sys.argv[1] if len(sys.argv) > 1 else "attacks/evil_envgrab.py"
    print(f"Scan de {chemin}\n")
    for r in scan(chemin):
        print(f"  [{r['verdict'].upper()}] {r['name']}")
        print(f"    score juge : {r['score']}")
        print(f"    alertes règles : {r['alertes']}")
        if r.get("severes"):
            print(f"    dont sévères  : {r['severes']}")
        print(f"    raison : {r['raison']}\n")