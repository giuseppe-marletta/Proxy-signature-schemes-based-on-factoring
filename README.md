# Proxy signature schemes based on factorting


Si tratta di un'implementazione prototipo dello schema di firma proxy basato sul factoring come descitto nel [paper](https://www.sciencedirect.com/science/article/abs/pii/S0020019002003678).  
L'implementazione è totalmente scritta in [c](<https://en.wikipedia.org/wiki/C_(programming_language)>) e usa le librerie [GMP](https://gmplib.org) e [Nettle](http://www.lysator.liu.se/~nisse/nettle/).

## Struttura del progetto

Il progetto è strutturato come segue:

```shell
.
├── include # contiene i file header
├── lib # contiene le librerie "utility" fornite dal professore Mario Di Raimondo
├── src # contiene i file sorgente
└── test # contiene il file test
```


## Compilazione

Per compilare il progetto, basta utilizzare il comando make:

```shell
make 
```

Una volta compilato, il test può essere esguito mediante il seguente comando:

```shell
./test-OwnerSigner <params>
```

## Utilizzo

```shell
./test-OwnerSigner [verbose|quiet|bench] [sec-lev <n>] [message <n>] [signers <n>]
```

```shell
# Viene indicata la scelta sull'output da fornire
./test-OwnerSigner [verbose|quiet|bench]
```

```shell
# Viene indicata la scelta sul livello di sicurezza simmetrico da impiegare (default 80)
./test-OwnerSigner [sec-lev <n>]
```

```shell
# Viene indicata la scelta sul messaggio personalizzato da utilizare (default .)
./test-OwnerSigner [message <n>]
```

```shell
# Viene indicata la scelta sul numero di firmatari proxy da includere negli schemi multifirma (default 5)
./test-OwnerSigner [signers <n>]
```


