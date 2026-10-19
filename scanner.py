"""scanner.py — combine règles + juge LLM et rend un verdict par outil."""

import os

from client import get_tools
from rules import check_rules_detail, SEVERE
from judge import judge_tool  # adapte si c'est llm_judge dans ton repo

# Jev : classifieur typé rapide en premier passage. ACTIVÉ par défaut ;
# mets USE_JEV=0 pour couper. Repli automatique sur le juge LLM si Jev est
# injoignable, donc activer ne casse jamais un scan.
USE_JEV = os.environ.get("USE_JEV", "1").strip().lower() in ("1", "true", "yes", "on")
JEV_CONF_MIN = float(os.environ.get("JEV_CONF_MIN", "0.6"))


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


def _juge(name, description, params):
    """Couche de jugement : Jev d'abord (si activé), juge LLM sinon.

    - USE_JEV désactivé -> juge LLM classique.
    - USE_JEV activé -> Jev (rapide/pas cher). S'il est assez sûr
      (confiance >= JEV_CONF_MIN) on garde son verdict ; sinon on escalade vers
      le juge LLM pour trancher ET obtenir l'explication. Si Jev échoue, on
      retombe proprement sur le juge LLM.
    Renvoie (score 0-10, raison). Une exception remonte au fail-closed.
    """
    if USE_JEV:
        try:
            from judge_jev import classify_jev
            jv = classify_jev(name, description, params)
            if jv.confidence >= JEV_CONF_MIN:
                return jv.danger, jv.reason
            v = judge_tool(name, description, params)
            return v.score, f"{jv.reason} — incertain -> juge LLM : {v.reason}"
        except Exception as e:
            v = judge_tool(name, description, params)
            return v.score, f"(Jev indisponible : {e}) juge LLM : {v.reason}"
    v = judge_tool(name, description, params)
    return v.score, v.reason


def _champs_a_scanner(name, description, params):
    """(source, texte) pour chaque zone passée aux règles.

    Un piège ne vit pas que dans la description : il peut se cacher dans le
    NOM de l'outil ou dans un PARAMÈTRE (son nom, sa description). On scanne
    donc toute la surface, en gardant la trace de la source de chaque alerte.
    """
    champs = [("nom", name or ""), ("description", description or "")]
    props = params.get("properties") if isinstance(params, dict) else None
    for pname, info in (props or {}).items():
        info = info if isinstance(info, dict) else {}
        morceaux = [pname] + [str(info[k]) for k in ("description", "title") if info.get(k)]
        champs.append((f"param:{pname}", " ".join(morceaux)))
    return champs


def scan_outil(name: str, description: str, params=None) -> dict:
    """Scanne toute la surface d'un outil (nom + description + params).

    Renvoie verdict + détails, dont la source de chaque alerte de règle.
    """
    # Règles appliquées à chaque zone ; on agrège les alertes uniques et on
    # note dans quelle(s) zone(s) chacune est apparue.
    severite = {}          # nom d'alerte -> sévérité
    sources = {}           # nom d'alerte -> set de zones
    for source, texte in _champs_a_scanner(name, description, params):
        for nom, sev in check_rules_detail(texte):
            severite[nom] = sev
            sources.setdefault(nom, set()).add(source)

    alertes_detail = list(severite.items())
    alertes = list(severite.keys())
    severes = [n for n, s in severite.items() if s == SEVERE]
    sources = {n: sorted(v) for n, v in sources.items()}

    # Juge LLM. Fail-closed : si l'appel échoue, on considère dangereux
    # plutôt que de laisser passer un outil non vérifié.
    try:
        score, raison = _juge(name, description, params)
    except Exception as e:
        return {
            "name": name,
            "verdict": "dangereux",
            "score": None,
            "alertes": alertes,
            "severes": severes,
            "sources": sources,
            "raison": f"Juge indisponible, blocage par sécurité ({e})",
        }

    return {
        "name": name,
        "verdict": _verdict(score, alertes_detail),
        "score": score,
        "alertes": alertes,
        "severes": severes,
        "sources": sources,
        "raison": raison,
    }


def scan(server_path: str) -> list:
    """Scanne tous les outils d'un serveur MCP. Renvoie un verdict par outil."""
    resultats = []
    for tool in get_tools(server_path):
        resultats.append(scan_outil(tool["name"], tool["description"], tool.get("params")))
    return resultats


if __name__ == "__main__":
    import sys
    chemin = sys.argv[1] if len(sys.argv) > 1 else "attacks/evil_envgrab.py"
    print(f"Scan de {chemin}\n")
    for r in scan(chemin):
        print(f"  [{r['verdict'].upper()}] {r['name']}")
        print(f"    score juge : {r['score']}")
        print(f"    alertes règles : {r['alertes']}")
        for nom in r["alertes"]:
            src = ", ".join(r.get("sources", {}).get(nom, []))
            sev = "sévère" if nom in r.get("severes", []) else "faible"
            print(f"       - {nom} ({sev}) — vu dans : {src}")
        print(f"    raison : {r['raison']}\n")