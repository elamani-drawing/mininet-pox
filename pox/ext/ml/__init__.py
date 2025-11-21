import time 

# Parameters
# longueur de la fenêtre d'agrégation
WINDOW_SECONDS = 10.0  
# intervalle pour vérifier/émettre (s)
EMIT_INTERVAL = 1.0   

def now():
    return time.time()
