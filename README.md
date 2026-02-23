# meow

Systeme de scan de port distribué.

**Alpha release hésitez pas à rapporter des bugs** 
*Le principal de la documentation est exposé dans le datastore* 

## quickstart 

### build

Si docker build est installé  (peut prendre un certain temps)
```
make dist
```

Sinon si vous avez un compilateur go juste 
```
make
```

### mode local

On lance d'abord le datastore qui écoute par défaut sur :

* 127.0.0.1:18080 pour la partie api 
* 127.0.0.1:4222 sur la partie nats par défaut

```bash
$ ./datastore 
```
Ensuite on attache le ou les grab, la version locale qui permet de lancer l'enrich et le finger sur localhost
```
$ ./grab local
```
et enfin le synscan qui peut etre contrôlé par le datastore si il est lancé en mode demon (et qui fait apparaitre l'onglet scan dans le datastore quand il détecte qu'un synscan est utilisable) :


```
$ ./synscan -d
```

### mode multi modules

**Pour avoir de la performance il est fortement recommandé de faire tourner le synscan et les grabbers sur des machines séparées**

```
$ ./datastore -nats-host 192.168.0.12 -nats-token natssecret -api-bind 192.168.0.12 -api-pass monsupertoken
$ ./grab enrich --nats-token natssecret --nats-url nats://192.168.0.12:4222
$ ./grab finger --nats-token natssecret --nats-url nats://192.168.0.12:4222
$ ./synscan -d --nats-token natssecret --nats-url nats://192.168.0.12:4222 # daemon mode
$ ./synscan --nats-token natssecret --nats-url nats://192.168.0.12:4222 -t 192.168.0.0/24 -P 50 # direct scan publish
```

## todo

* plein de modules à terminer/ajouter 
* export gnmap xml?
* faire des scripts pour l'update auto des bases geoip cdncheck etc