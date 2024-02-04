# сборка образа 
./control.sh deth1 build

# Запуск семейсва  в рабочем режиме - для работы с уздом 1 кластера 1  
./control.sh deth1   up -d
# остановить семейство 
./control.sh deth1   down


# запуск семейства в режиме тест
# (cd families/dgt_eth;deth-tp -vv -C tcp://validator-dgt-c1-1:4104)
#

# ключи для новых аккаунтов
dgt keygen --key-dir /project/peer/keys  my
dgt keygen --key-dir /project/peer/keys  my1
# для  имени смарт контракта на основе ключа
dgt keygen --key-dir /project/peer/keys   smart
# создаем аккаунт
deth account -key /project/peer/keys/my.priv
# проверем  состояние
deth show /project/peer/keys/my.priv
#  пересылаем монеты с нового  аккаунта - при  этом он создается 
deth send -key /project/peer/keys/my.priv /project/peer/keys/my1.priv 1
# проверяем  состояние  второго аккаунта
deth show /project/peer/keys/my1.priv

#   создать смарт в режиме перезаписи имя смарт контракта вычисляется из -skey параметра
deth smart dgtkeys -p test-app/intkey.sol -comp -upd -key /project/peer/keys/my.priv -skey /project/peer/keys/smart.priv
# проверяем  состояние смарт контракта 
deth show /project/peer/keys/smart.priv
#  выполняем  метод смарт контракта от имени пользователя  с ключом /project/peer/keys/my.priv
deth call /project/peer/keys/smart.priv get -a 1 -key /project/peer/keys/my.priv

#  выполнить метод dec  для  ячейки 0  - если значение равно нулю то будет ошибка
deth call /project/peer/keys/smart.priv dec -a 0   -key /project/peer/keys/my.priv
# получить значение ячейки 0
deth call /project/peer/keys/smart.priv get -a 0   -key /project/peer/keys/wkey.priv
# увеличить  значение ячейки 0 на  +1
deth call /project/peer/keys/smart.priv inc -a 0   -key /project/peer/keys/wkey.priv
# установить конкретное значение  ячейки 0=3
deth call /project/peer/keys/smart.priv set -a 0,3  -key /project/peer/keys/wkey.priv

# посмотреть все 
deth list
# детально давать описание функций смарт контракта 
deth list -v
# только  смарт контракты

deth list -tp smart
# только аккаунты
deth list -tp account
