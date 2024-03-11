# Допустимые типы хостов для API сторонних сервисов

| Сервис           | Допустимые типы     | Документация                                          | Квоты                                 |
|------------------|---------------------|-------------------------------------------------------|---------------------------------------|
| VirusTotal       | IP, ~~URL~~, Domain | https://docs.virustotal.com/reference/overview        | 15500 в месяц, 500 в день, 4 в минуту |
| IP Quality Score | IP, URL, EMail      | https://www.ipqualityscore.com/documentation/overview | 5000 в месяц                          |
| CrowdSec CTI     | IP                  | https://app.crowdsec.net/cti                          | 10 за 2 часа, 50 в день               |
| Shodan           | IP                  | https://developer.shodan.io/api                       | 500 в месяц                           |
|

> В VitusTotal допустимо сканирование URL, но только в 2 запроса. Возможна дальнейшая доработка, на момент 11.03
> доработка не требуется.