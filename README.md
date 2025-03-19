<!-- TOC --><a name="-"></a>
# Методы шифрования: Руководство для начинающих программистов

<!-- TOC --><a name=""></a>
## Введение

Эта документация является частью проектной работы. В ней вы научитесь использовать алгоритмы шифрования данных, узнаете о их работе и областях применения каждого из них. 
В современном мире защита информации является очень острым вопросом. Одним из способ её защиты — это шифрование данных, которое помогает скрыть информацию от чужих глаз, даже если произошла её утечка.
В первую очередь документация предназначена для:
- Начинающим программистам, которые знают основы Python.
- Тем, кто хочет понять, как шифровать данные и зачем это нужно.
- Всем, кто интересуется историей и практическим применением криптографии.
Главная цель — помочь начинающим программистам освоит шифрование данных на языке программирования Python и предостеречь их от совершения частых ошибок. 

---

<!-- TOC --><a name="-1"></a>
## Оглавление

<!-- TOC start (generated with https://github.com/derlin/bitdowntoc) -->

- [Методы шифрования: Руководство для начинающих программистов](#-)
   * [Введение](#)
   * [Оглавление](#-1)
- [История шифров](#--1)
- [Основные понятия](#--2)
- [Простые методы шифрования](#--3)
   * [Шифр Цезаря ](#--4)
   * [Шифр Виженера](#--5)
   * [Шифрование с помощью XOR](#-xor)
   * [Заключение](#-2)
- [Продвинутые методы шифрования](#--6)
   * [DES - первый в мире открытый стандарт шифрования данных](#des-)
   * [AES](#aes)
   * [RSA](#rsa)
   * [Введение в библиотеку ](#--7)
      + [MODE_ECB](#mode_ecb)
      + [MODE_CBC ](#mode_cbc)
      + [MODE_CFB](#mode_cfb)
      + [MODE_OFB](#mode_ofb)
      + [MODE_CTR](#mode_ctr)
      + [MODE_OPENPGP](#mode_openpgp)
      + [MODE_EAX](#mode_eax)
      + [MODE_CCM](#mode_ccm)
      + [MODE_SIV](#mode_siv)
      + [MODE_GCM](#mode_gcm)
      + [MODE_OCB](#mode_ocb)
      + [OAEP](#oaep)
      + [v1.5](#v15)
      + [PSS](#pss)
- [Частые ошибки](#--8)
   * [Симметричные шифры](#--9)
   * [Асимметричные шифры](#--10)
   * [Общие ошибки](#--11)
   * [Как избежать ошибок](#--12)

<!-- TOC end -->

---

<!-- TOC --><a name="--1"></a>
# История шифров

Шифры появились ещё до нашей эры. Люди хотели сохранять и передавать информацию, скрывая её от посторонних «глаз». Один из самых известных методов шифрования – шифр Цезаря. Этот шифр – простая форма шифра замены, в которой каждая буква открытого текста заменяется на определённую букву или символ из другой таблицы символов. Чаще всего криптография применялась в политической и дипломатической сферах. В Средневековье криптография стала более популярной: появились первые формы криптоанализа — науки о расшифровке зашифрованных сообщений без знания ключа.

В Новое время криптография приобрела стратегическое значение в военном деле. Ярким примером развития криптографии стала разработка нацистами во время Второй мировой войны шифра Энигма, который смогли взломать британские криптоаналитики, что очень помогло в ходе войны. С приходом компьютерных технологий алгоритмы шифрования стали более разнообразными и сложными. Криптография развивается каждый день, что позволяет создавать всё более продвинутые системы для хранения и защиты данных.


<!-- TOC --><a name="--2"></a>
# Основные понятия

Основные понятия и термины, которые нужно знать для лучшего понимания устройства шифрования данных.

**Шифр** — это алгоритм или метод шифрования, который преобразует исходный текст в форму, нечитаемую для посторонних лиц.

**Открытый текст** — это исходный текст, который нужно зашифровать. Это может быть любой вид информации, включая текст, изображения, звук и т. д.

**Зашифрованный текст** — это результат применения шифра к открытому тексту. Зашифрованный текст должен быть нечитаемым для всех, кроме того, кто имеет ключ для расшифровки.

**Ключ** — это строка символов или чисел, используемая для шифрования и расшифровки сообщения. Ключ может быть секретным (закрытым) или общедоступным (открытым), в зависимости от используемого алгоритма.

**Симметричное шифрование** — это метод шифрования, при котором один и тот же ключ используется для шифрования и расшифровки сообщения. Примеры симметричных алгоритмов: DES, AES, Blowfish.

**Асимметричное шифрование** — это метод шифрования, при котором используется пара ключей: открытый и закрытый. Открытый ключ может быть общедоступным, а закрытый ключ должен оставаться секретным. Примеры асимметричных алгоритмов: RSA, PGP.

**Хэш-функция** — это алгоритм, который преобразует произвольные данные (например, текст или файл) в хэш-код фиксированного размера. Хэш-функции используются для проверки целостности данных и создания цифровых подписей.

**Цифровая подпись** — это электронная подпись, которая гарантирует, что сообщение было отправлено конкретным лицом и не было изменено в процессе передачи. Цифровые подписи создаются с помощью хэш-функций и асимметричных алгоритмов.


<!-- TOC --><a name="--3"></a>
# Простые методы шифрования

В этой главе будут приведены простые способы шифрования данных, надёжность которых очень мала.


<!-- TOC --><a name="--4"></a>
## Шифр Цезаря 
— это один из самых простых и широко известных методов шифрования, который был использован уже в древности. Он основывается на замене каждой буквы на другую, которая находится через определённое количество позиций (m) в алфавите. Чаще всего используется в компьютерных играх, онлайн форумах, но не с целью защиты данных, а для усложнения её прочтения. Для примера можно зашифровать слово «Шифр» используя шифр Цезаря и смещение на 6 позиций (m = 6). 
Напишем номера букв в начальном слове: 

| Буква | Порядковый номер (n) |
| ----- | -------------------- |
| Ш     | 26                   |
| И     | 10                   |
| Ф     | 22                   |
| Р     | 18                   |

Применим сдвиг (прибавим к порядковому номеру смещение):

| Начальное значение (n) | Конечное значение (n + m) |
| ---------------------- | ------------------------- |
| 26                     | 32                        |
| 10                     | 16                        |
| 22                     | 28                        |
| 18                     | 24                        |

Запишем буквы, стоящие на полученных местах:

| Полученное значение | Соответствующая буква |
| ------------------- | --------------------- |
| 32                  | Ю                     |
| 16                  | О                     |
| 28                  | Ъ                     |
| 24                  | Ц                     |

Таким образом мы получаем зашифрованный текст «Юоъц», который при смещении в -6 можно превратить в изначальный текст «Шифр». Так же можно использовать специальную таблицу, для получения буквы после сдвига, где название столбцов - это сдвиг, а название строк - буква открытого текста.

<details>
	<summary><b>Таблица значений</b></summary> 

<html>
	<body>
		  <table border="0" cellpadding="0" cellspacing="0" id="sheet0" class="sheet0 gridlines">
			<col class="col0">
			<col class="col1">
			<col class="col2">
			<col class="col3">
			<col class="col4">
			<col class="col5">
			<col class="col6">
			<col class="col7">
			<col class="col8">
			<col class="col9">
			<col class="col10">
			<col class="col11">
			<col class="col12">
			<col class="col13">
			<col class="col14">
			<col class="col15">
			<col class="col16">
			<col class="col17">
			<col class="col18">
			<col class="col19">
			<col class="col20">
			<col class="col21">
			<col class="col22">
			<col class="col23">
			<col class="col24">
			<col class="col25">
			<col class="col26">
			<col class="col27">
			<col class="col28">
			<col class="col29">
			<col class="col30">
			<col class="col31">
			<col class="col32">
			<col class="col33">
			<tbody>
			  <tr class="row1">
				<td class="column0 style1 s">Смещение / Буква</td>
				<td class="column1 style3 s">1</td>
				<td class="column2 style3 s">2</td>
				<td class="column3 style3 s">3</td>
				<td class="column4 style3 s">4</td>
				<td class="column5 style3 s">5</td>
				<td class="column6 style3 s">6</td>
				<td class="column7 style3 s">7</td>
				<td class="column8 style3 s">8</td>
				<td class="column9 style3 s">9</td>
				<td class="column10 style3 s">10</td>
				<td class="column11 style3 s">11</td>
				<td class="column12 style3 s">12</td>
				<td class="column13 style3 s">13</td>
				<td class="column14 style3 s">14</td>
				<td class="column15 style3 s">15</td>
				<td class="column16 style3 s">16</td>
				<td class="column17 style3 s">17</td>
				<td class="column18 style3 s">18</td>
				<td class="column19 style3 s">19</td>
				<td class="column20 style3 s">20</td>
				<td class="column21 style3 s">21</td>
				<td class="column22 style3 s">22</td>
				<td class="column23 style3 s">23</td>
				<td class="column24 style3 s">24</td>
				<td class="column25 style3 s">25</td>
				<td class="column26 style3 s">26</td>
				<td class="column27 style3 s">27</td>
				<td class="column28 style3 s">28</td>
				<td class="column29 style3 s">29</td>
				<td class="column30 style3 s">30</td>
				<td class="column31 style3 s">31</td>
				<td class="column32 style3 s">32</td>
				<td class="column33 style3 s">33</td>
			  </tr>
			  <tr class="row2">
				<td class="column0 style3 s">А</td>
				<td class="column1 style4 s">Б</td>
				<td class="column2 style5 s">В</td>
				<td class="column3 style4 s">Г</td>
				<td class="column4 style5 s">Д</td>
				<td class="column5 style4 s">Е</td>
				<td class="column6 style5 s">Ё</td>
				<td class="column7 style4 s">Ж</td>
				<td class="column8 style5 s">З</td>
				<td class="column9 style4 s">И</td>
				<td class="column10 style5 s">Й</td>
				<td class="column11 style4 s">К</td>
				<td class="column12 style5 s">Л</td>
				<td class="column13 style4 s">М</td>
				<td class="column14 style5 s">Н</td>
				<td class="column15 style4 s">О</td>
				<td class="column16 style5 s">П</td>
				<td class="column17 style4 s">Р</td>
				<td class="column18 style5 s">С</td>
				<td class="column19 style4 s">Т</td>
				<td class="column20 style5 s">У</td>
				<td class="column21 style4 s">Ф</td>
				<td class="column22 style5 s">Х</td>
				<td class="column23 style4 s">Ц</td>
				<td class="column24 style5 s">Ч</td>
				<td class="column25 style4 s">Ш</td>
				<td class="column26 style5 s">Щ</td>
				<td class="column27 style4 s">Ъ</td>
				<td class="column28 style5 s">Ы</td>
				<td class="column29 style4 s">Ь</td>
				<td class="column30 style5 s">Э</td>
				<td class="column31 style4 s">Ю</td>
				<td class="column32 style5 s">Я</td>
				<td class="column33 style4 s">А</td>
			  </tr>
			  <tr class="row3">
				<td class="column0 style3 s">Б</td>
				<td class="column1 style5 s">В</td>
				<td class="column2 style4 s">Г</td>
				<td class="column3 style5 s">Д</td>
				<td class="column4 style4 s">Е</td>
				<td class="column5 style5 s">Ё</td>
				<td class="column6 style4 s">Ж</td>
				<td class="column7 style5 s">З</td>
				<td class="column8 style4 s">И</td>
				<td class="column9 style5 s">Й</td>
				<td class="column10 style4 s">К</td>
				<td class="column11 style5 s">Л</td>
				<td class="column12 style4 s">М</td>
				<td class="column13 style5 s">Н</td>
				<td class="column14 style4 s">О</td>
				<td class="column15 style5 s">П</td>
				<td class="column16 style4 s">Р</td>
				<td class="column17 style5 s">С</td>
				<td class="column18 style4 s">Т</td>
				<td class="column19 style5 s">У</td>
				<td class="column20 style4 s">Ф</td>
				<td class="column21 style5 s">Х</td>
				<td class="column22 style4 s">Ц</td>
				<td class="column23 style5 s">Ч</td>
				<td class="column24 style4 s">Ш</td>
				<td class="column25 style5 s">Щ</td>
				<td class="column26 style4 s">Ъ</td>
				<td class="column27 style5 s">Ы</td>
				<td class="column28 style4 s">Ь</td>
				<td class="column29 style5 s">Э</td>
				<td class="column30 style4 s">Ю</td>
				<td class="column31 style5 s">Я</td>
				<td class="column32 style4 s">А</td>
				<td class="column33 style5 s">Б</td>
			  </tr>
			  <tr class="row4">
				<td class="column0 style3 s">В</td>
				<td class="column1 style4 s">Г</td>
				<td class="column2 style5 s">Д</td>
				<td class="column3 style4 s">Е</td>
				<td class="column4 style5 s">Ё</td>
				<td class="column5 style4 s">Ж</td>
				<td class="column6 style5 s">З</td>
				<td class="column7 style4 s">И</td>
				<td class="column8 style5 s">Й</td>
				<td class="column9 style4 s">К</td>
				<td class="column10 style5 s">Л</td>
				<td class="column11 style4 s">М</td>
				<td class="column12 style5 s">Н</td>
				<td class="column13 style4 s">О</td>
				<td class="column14 style5 s">П</td>
				<td class="column15 style4 s">Р</td>
				<td class="column16 style5 s">С</td>
				<td class="column17 style4 s">Т</td>
				<td class="column18 style5 s">У</td>
				<td class="column19 style4 s">Ф</td>
				<td class="column20 style5 s">Х</td>
				<td class="column21 style4 s">Ц</td>
				<td class="column22 style5 s">Ч</td>
				<td class="column23 style4 s">Ш</td>
				<td class="column24 style5 s">Щ</td>
				<td class="column25 style4 s">Ъ</td>
				<td class="column26 style5 s">Ы</td>
				<td class="column27 style4 s">Ь</td>
				<td class="column28 style5 s">Э</td>
				<td class="column29 style4 s">Ю</td>
				<td class="column30 style5 s">Я</td>
				<td class="column31 style4 s">А</td>
				<td class="column32 style5 s">Б</td>
				<td class="column33 style4 s">В</td>
			  </tr>
			  <tr class="row5">
				<td class="column0 style3 s">Г</td>
				<td class="column1 style5 s">Д</td>
				<td class="column2 style4 s">Е</td>
				<td class="column3 style5 s">Ё</td>
				<td class="column4 style4 s">Ж</td>
				<td class="column5 style5 s">З</td>
				<td class="column6 style4 s">И</td>
				<td class="column7 style5 s">Й</td>
				<td class="column8 style4 s">К</td>
				<td class="column9 style5 s">Л</td>
				<td class="column10 style4 s">М</td>
				<td class="column11 style5 s">Н</td>
				<td class="column12 style4 s">О</td>
				<td class="column13 style5 s">П</td>
				<td class="column14 style4 s">Р</td>
				<td class="column15 style5 s">С</td>
				<td class="column16 style4 s">Т</td>
				<td class="column17 style5 s">У</td>
				<td class="column18 style4 s">Ф</td>
				<td class="column19 style5 s">Х</td>
				<td class="column20 style4 s">Ц</td>
				<td class="column21 style5 s">Ч</td>
				<td class="column22 style4 s">Ш</td>
				<td class="column23 style5 s">Щ</td>
				<td class="column24 style4 s">Ъ</td>
				<td class="column25 style5 s">Ы</td>
				<td class="column26 style4 s">Ь</td>
				<td class="column27 style5 s">Э</td>
				<td class="column28 style4 s">Ю</td>
				<td class="column29 style5 s">Я</td>
				<td class="column30 style4 s">А</td>
				<td class="column31 style5 s">Б</td>
				<td class="column32 style4 s">В</td>
				<td class="column33 style5 s">Г</td>
			  </tr>
			  <tr class="row6">
				<td class="column0 style3 s">Д</td>
				<td class="column1 style4 s">Е</td>
				<td class="column2 style5 s">Ё</td>
				<td class="column3 style4 s">Ж</td>
				<td class="column4 style5 s">З</td>
				<td class="column5 style4 s">И</td>
				<td class="column6 style5 s">Й</td>
				<td class="column7 style4 s">К</td>
				<td class="column8 style5 s">Л</td>
				<td class="column9 style4 s">М</td>
				<td class="column10 style5 s">Н</td>
				<td class="column11 style4 s">О</td>
				<td class="column12 style5 s">П</td>
				<td class="column13 style4 s">Р</td>
				<td class="column14 style5 s">С</td>
				<td class="column15 style4 s">Т</td>
				<td class="column16 style5 s">У</td>
				<td class="column17 style4 s">Ф</td>
				<td class="column18 style5 s">Х</td>
				<td class="column19 style4 s">Ц</td>
				<td class="column20 style5 s">Ч</td>
				<td class="column21 style4 s">Ш</td>
				<td class="column22 style5 s">Щ</td>
				<td class="column23 style4 s">Ъ</td>
				<td class="column24 style5 s">Ы</td>
				<td class="column25 style4 s">Ь</td>
				<td class="column26 style5 s">Э</td>
				<td class="column27 style4 s">Ю</td>
				<td class="column28 style5 s">Я</td>
				<td class="column29 style4 s">А</td>
				<td class="column30 style5 s">Б</td>
				<td class="column31 style4 s">В</td>
				<td class="column32 style5 s">Г</td>
				<td class="column33 style4 s">Д</td>
			  </tr>
			  <tr class="row7">
				<td class="column0 style3 s">Е</td>
				<td class="column1 style5 s">Ё</td>
				<td class="column2 style4 s">Ж</td>
				<td class="column3 style5 s">З</td>
				<td class="column4 style4 s">И</td>
				<td class="column5 style5 s">Й</td>
				<td class="column6 style4 s">К</td>
				<td class="column7 style5 s">Л</td>
				<td class="column8 style4 s">М</td>
				<td class="column9 style5 s">Н</td>
				<td class="column10 style4 s">О</td>
				<td class="column11 style5 s">П</td>
				<td class="column12 style4 s">Р</td>
				<td class="column13 style5 s">С</td>
				<td class="column14 style4 s">Т</td>
				<td class="column15 style5 s">У</td>
				<td class="column16 style4 s">Ф</td>
				<td class="column17 style5 s">Х</td>
				<td class="column18 style4 s">Ц</td>
				<td class="column19 style5 s">Ч</td>
				<td class="column20 style4 s">Ш</td>
				<td class="column21 style5 s">Щ</td>
				<td class="column22 style4 s">Ъ</td>
				<td class="column23 style5 s">Ы</td>
				<td class="column24 style4 s">Ь</td>
				<td class="column25 style5 s">Э</td>
				<td class="column26 style4 s">Ю</td>
				<td class="column27 style5 s">Я</td>
				<td class="column28 style4 s">А</td>
				<td class="column29 style5 s">Б</td>
				<td class="column30 style4 s">В</td>
				<td class="column31 style5 s">Г</td>
				<td class="column32 style4 s">Д</td>
				<td class="column33 style5 s">Е</td>
			  </tr>
			  <tr class="row8">
				<td class="column0 style3 s">Ё</td>
				<td class="column1 style4 s">Ж</td>
				<td class="column2 style5 s">З</td>
				<td class="column3 style4 s">И</td>
				<td class="column4 style5 s">Й</td>
				<td class="column5 style4 s">К</td>
				<td class="column6 style5 s">Л</td>
				<td class="column7 style4 s">М</td>
				<td class="column8 style5 s">Н</td>
				<td class="column9 style4 s">О</td>
				<td class="column10 style5 s">П</td>
				<td class="column11 style4 s">Р</td>
				<td class="column12 style5 s">С</td>
				<td class="column13 style4 s">Т</td>
				<td class="column14 style5 s">У</td>
				<td class="column15 style4 s">Ф</td>
				<td class="column16 style5 s">Х</td>
				<td class="column17 style4 s">Ц</td>
				<td class="column18 style5 s">Ч</td>
				<td class="column19 style4 s">Ш</td>
				<td class="column20 style5 s">Щ</td>
				<td class="column21 style4 s">Ъ</td>
				<td class="column22 style5 s">Ы</td>
				<td class="column23 style4 s">Ь</td>
				<td class="column24 style5 s">Э</td>
				<td class="column25 style4 s">Ю</td>
				<td class="column26 style5 s">Я</td>
				<td class="column27 style4 s">А</td>
				<td class="column28 style5 s">Б</td>
				<td class="column29 style4 s">В</td>
				<td class="column30 style5 s">Г</td>
				<td class="column31 style4 s">Д</td>
				<td class="column32 style5 s">Е</td>
				<td class="column33 style4 s">Ё</td>
			  </tr>
			  <tr class="row9">
				<td class="column0 style3 s">Ж</td>
				<td class="column1 style5 s">З</td>
				<td class="column2 style4 s">И</td>
				<td class="column3 style5 s">Й</td>
				<td class="column4 style4 s">К</td>
				<td class="column5 style5 s">Л</td>
				<td class="column6 style4 s">М</td>
				<td class="column7 style5 s">Н</td>
				<td class="column8 style4 s">О</td>
				<td class="column9 style5 s">П</td>
				<td class="column10 style4 s">Р</td>
				<td class="column11 style5 s">С</td>
				<td class="column12 style4 s">Т</td>
				<td class="column13 style5 s">У</td>
				<td class="column14 style4 s">Ф</td>
				<td class="column15 style5 s">Х</td>
				<td class="column16 style4 s">Ц</td>
				<td class="column17 style5 s">Ч</td>
				<td class="column18 style4 s">Ш</td>
				<td class="column19 style5 s">Щ</td>
				<td class="column20 style4 s">Ъ</td>
				<td class="column21 style5 s">Ы</td>
				<td class="column22 style4 s">Ь</td>
				<td class="column23 style5 s">Э</td>
				<td class="column24 style4 s">Ю</td>
				<td class="column25 style5 s">Я</td>
				<td class="column26 style4 s">А</td>
				<td class="column27 style5 s">Б</td>
				<td class="column28 style4 s">В</td>
				<td class="column29 style5 s">Г</td>
				<td class="column30 style4 s">Д</td>
				<td class="column31 style5 s">Е</td>
				<td class="column32 style4 s">Ё</td>
				<td class="column33 style5 s">Ж</td>
			  </tr>
			  <tr class="row10">
				<td class="column0 style3 s">З</td>
				<td class="column1 style4 s">И</td>
				<td class="column2 style5 s">Й</td>
				<td class="column3 style4 s">К</td>
				<td class="column4 style5 s">Л</td>
				<td class="column5 style4 s">М</td>
				<td class="column6 style5 s">Н</td>
				<td class="column7 style4 s">О</td>
				<td class="column8 style5 s">П</td>
				<td class="column9 style4 s">Р</td>
				<td class="column10 style5 s">С</td>
				<td class="column11 style4 s">Т</td>
				<td class="column12 style5 s">У</td>
				<td class="column13 style4 s">Ф</td>
				<td class="column14 style5 s">Х</td>
				<td class="column15 style4 s">Ц</td>
				<td class="column16 style5 s">Ч</td>
				<td class="column17 style4 s">Ш</td>
				<td class="column18 style5 s">Щ</td>
				<td class="column19 style4 s">Ъ</td>
				<td class="column20 style5 s">Ы</td>
				<td class="column21 style4 s">Ь</td>
				<td class="column22 style5 s">Э</td>
				<td class="column23 style4 s">Ю</td>
				<td class="column24 style5 s">Я</td>
				<td class="column25 style4 s">А</td>
				<td class="column26 style5 s">Б</td>
				<td class="column27 style4 s">В</td>
				<td class="column28 style5 s">Г</td>
				<td class="column29 style4 s">Д</td>
				<td class="column30 style5 s">Е</td>
				<td class="column31 style4 s">Ё</td>
				<td class="column32 style5 s">Ж</td>
				<td class="column33 style4 s">З</td>
			  </tr>
			  <tr class="row11">
				<td class="column0 style3 s">И</td>
				<td class="column1 style5 s">Й</td>
				<td class="column2 style4 s">К</td>
				<td class="column3 style5 s">Л</td>
				<td class="column4 style4 s">М</td>
				<td class="column5 style5 s">Н</td>
				<td class="column6 style4 s">О</td>
				<td class="column7 style5 s">П</td>
				<td class="column8 style4 s">Р</td>
				<td class="column9 style5 s">С</td>
				<td class="column10 style4 s">Т</td>
				<td class="column11 style5 s">У</td>
				<td class="column12 style4 s">Ф</td>
				<td class="column13 style5 s">Х</td>
				<td class="column14 style4 s">Ц</td>
				<td class="column15 style5 s">Ч</td>
				<td class="column16 style4 s">Ш</td>
				<td class="column17 style5 s">Щ</td>
				<td class="column18 style4 s">Ъ</td>
				<td class="column19 style5 s">Ы</td>
				<td class="column20 style4 s">Ь</td>
				<td class="column21 style5 s">Э</td>
				<td class="column22 style4 s">Ю</td>
				<td class="column23 style5 s">Я</td>
				<td class="column24 style4 s">А</td>
				<td class="column25 style5 s">Б</td>
				<td class="column26 style4 s">В</td>
				<td class="column27 style5 s">Г</td>
				<td class="column28 style4 s">Д</td>
				<td class="column29 style5 s">Е</td>
				<td class="column30 style4 s">Ё</td>
				<td class="column31 style5 s">Ж</td>
				<td class="column32 style4 s">З</td>
				<td class="column33 style5 s">И</td>
			  </tr>
			  <tr class="row12">
				<td class="column0 style3 s">Й</td>
				<td class="column1 style4 s">К</td>
				<td class="column2 style5 s">Л</td>
				<td class="column3 style4 s">М</td>
				<td class="column4 style5 s">Н</td>
				<td class="column5 style4 s">О</td>
				<td class="column6 style5 s">П</td>
				<td class="column7 style4 s">Р</td>
				<td class="column8 style5 s">С</td>
				<td class="column9 style4 s">Т</td>
				<td class="column10 style5 s">У</td>
				<td class="column11 style4 s">Ф</td>
				<td class="column12 style5 s">Х</td>
				<td class="column13 style4 s">Ц</td>
				<td class="column14 style5 s">Ч</td>
				<td class="column15 style4 s">Ш</td>
				<td class="column16 style5 s">Щ</td>
				<td class="column17 style4 s">Ъ</td>
				<td class="column18 style5 s">Ы</td>
				<td class="column19 style4 s">Ь</td>
				<td class="column20 style5 s">Э</td>
				<td class="column21 style4 s">Ю</td>
				<td class="column22 style5 s">Я</td>
				<td class="column23 style4 s">А</td>
				<td class="column24 style5 s">Б</td>
				<td class="column25 style4 s">В</td>
				<td class="column26 style5 s">Г</td>
				<td class="column27 style4 s">Д</td>
				<td class="column28 style5 s">Е</td>
				<td class="column29 style4 s">Ё</td>
				<td class="column30 style5 s">Ж</td>
				<td class="column31 style4 s">З</td>
				<td class="column32 style5 s">И</td>
				<td class="column33 style4 s">Й</td>
			  </tr>
			  <tr class="row13">
				<td class="column0 style3 s">К</td>
				<td class="column1 style5 s">Л</td>
				<td class="column2 style4 s">М</td>
				<td class="column3 style5 s">Н</td>
				<td class="column4 style4 s">О</td>
				<td class="column5 style5 s">П</td>
				<td class="column6 style4 s">Р</td>
				<td class="column7 style5 s">С</td>
				<td class="column8 style4 s">Т</td>
				<td class="column9 style5 s">У</td>
				<td class="column10 style4 s">Ф</td>
				<td class="column11 style5 s">Х</td>
				<td class="column12 style4 s">Ц</td>
				<td class="column13 style5 s">Ч</td>
				<td class="column14 style4 s">Ш</td>
				<td class="column15 style5 s">Щ</td>
				<td class="column16 style4 s">Ъ</td>
				<td class="column17 style5 s">Ы</td>
				<td class="column18 style4 s">Ь</td>
				<td class="column19 style5 s">Э</td>
				<td class="column20 style4 s">Ю</td>
				<td class="column21 style5 s">Я</td>
				<td class="column22 style4 s">А</td>
				<td class="column23 style5 s">Б</td>
				<td class="column24 style4 s">В</td>
				<td class="column25 style5 s">Г</td>
				<td class="column26 style4 s">Д</td>
				<td class="column27 style5 s">Е</td>
				<td class="column28 style4 s">Ё</td>
				<td class="column29 style5 s">Ж</td>
				<td class="column30 style4 s">З</td>
				<td class="column31 style5 s">И</td>
				<td class="column32 style4 s">Й</td>
				<td class="column33 style5 s">К</td>
			  </tr>
			  <tr class="row14">
				<td class="column0 style3 s">Л</td>
				<td class="column1 style4 s">М</td>
				<td class="column2 style5 s">Н</td>
				<td class="column3 style4 s">О</td>
				<td class="column4 style5 s">П</td>
				<td class="column5 style4 s">Р</td>
				<td class="column6 style5 s">С</td>
				<td class="column7 style4 s">Т</td>
				<td class="column8 style5 s">У</td>
				<td class="column9 style4 s">Ф</td>
				<td class="column10 style5 s">Х</td>
				<td class="column11 style4 s">Ц</td>
				<td class="column12 style5 s">Ч</td>
				<td class="column13 style4 s">Ш</td>
				<td class="column14 style5 s">Щ</td>
				<td class="column15 style4 s">Ъ</td>
				<td class="column16 style5 s">Ы</td>
				<td class="column17 style4 s">Ь</td>
				<td class="column18 style5 s">Э</td>
				<td class="column19 style4 s">Ю</td>
				<td class="column20 style5 s">Я</td>
				<td class="column21 style4 s">А</td>
				<td class="column22 style5 s">Б</td>
				<td class="column23 style4 s">В</td>
				<td class="column24 style5 s">Г</td>
				<td class="column25 style4 s">Д</td>
				<td class="column26 style5 s">Е</td>
				<td class="column27 style4 s">Ё</td>
				<td class="column28 style5 s">Ж</td>
				<td class="column29 style4 s">З</td>
				<td class="column30 style5 s">И</td>
				<td class="column31 style4 s">Й</td>
				<td class="column32 style5 s">К</td>
				<td class="column33 style4 s">Л</td>
			  </tr>
			  <tr class="row15">
				<td class="column0 style3 s">М</td>
				<td class="column1 style5 s">Н</td>
				<td class="column2 style4 s">О</td>
				<td class="column3 style5 s">П</td>
				<td class="column4 style4 s">Р</td>
				<td class="column5 style5 s">С</td>
				<td class="column6 style4 s">Т</td>
				<td class="column7 style5 s">У</td>
				<td class="column8 style4 s">Ф</td>
				<td class="column9 style5 s">Х</td>
				<td class="column10 style4 s">Ц</td>
				<td class="column11 style5 s">Ч</td>
				<td class="column12 style4 s">Ш</td>
				<td class="column13 style5 s">Щ</td>
				<td class="column14 style4 s">Ъ</td>
				<td class="column15 style5 s">Ы</td>
				<td class="column16 style4 s">Ь</td>
				<td class="column17 style5 s">Э</td>
				<td class="column18 style4 s">Ю</td>
				<td class="column19 style5 s">Я</td>
				<td class="column20 style4 s">А</td>
				<td class="column21 style5 s">Б</td>
				<td class="column22 style4 s">В</td>
				<td class="column23 style5 s">Г</td>
				<td class="column24 style4 s">Д</td>
				<td class="column25 style5 s">Е</td>
				<td class="column26 style4 s">Ё</td>
				<td class="column27 style5 s">Ж</td>
				<td class="column28 style4 s">З</td>
				<td class="column29 style5 s">И</td>
				<td class="column30 style4 s">Й</td>
				<td class="column31 style5 s">К</td>
				<td class="column32 style4 s">Л</td>
				<td class="column33 style5 s">М</td>
			  </tr>
			  <tr class="row16">
				<td class="column0 style3 s">Н</td>
				<td class="column1 style4 s">О</td>
				<td class="column2 style5 s">П</td>
				<td class="column3 style4 s">Р</td>
				<td class="column4 style5 s">С</td>
				<td class="column5 style4 s">Т</td>
				<td class="column6 style5 s">У</td>
				<td class="column7 style4 s">Ф</td>
				<td class="column8 style5 s">Х</td>
				<td class="column9 style4 s">Ц</td>
				<td class="column10 style5 s">Ч</td>
				<td class="column11 style4 s">Ш</td>
				<td class="column12 style5 s">Щ</td>
				<td class="column13 style4 s">Ъ</td>
				<td class="column14 style5 s">Ы</td>
				<td class="column15 style4 s">Ь</td>
				<td class="column16 style5 s">Э</td>
				<td class="column17 style4 s">Ю</td>
				<td class="column18 style5 s">Я</td>
				<td class="column19 style4 s">А</td>
				<td class="column20 style5 s">Б</td>
				<td class="column21 style4 s">В</td>
				<td class="column22 style5 s">Г</td>
				<td class="column23 style4 s">Д</td>
				<td class="column24 style5 s">Е</td>
				<td class="column25 style4 s">Ё</td>
				<td class="column26 style5 s">Ж</td>
				<td class="column27 style4 s">З</td>
				<td class="column28 style5 s">И</td>
				<td class="column29 style4 s">Й</td>
				<td class="column30 style5 s">К</td>
				<td class="column31 style4 s">Л</td>
				<td class="column32 style5 s">М</td>
				<td class="column33 style4 s">Н</td>
			  </tr>
			  <tr class="row17">
				<td class="column0 style3 s">О</td>
				<td class="column1 style5 s">П</td>
				<td class="column2 style4 s">Р</td>
				<td class="column3 style5 s">С</td>
				<td class="column4 style4 s">Т</td>
				<td class="column5 style5 s">У</td>
				<td class="column6 style4 s">Ф</td>
				<td class="column7 style5 s">Х</td>
				<td class="column8 style4 s">Ц</td>
				<td class="column9 style5 s">Ч</td>
				<td class="column10 style4 s">Ш</td>
				<td class="column11 style5 s">Щ</td>
				<td class="column12 style4 s">Ъ</td>
				<td class="column13 style5 s">Ы</td>
				<td class="column14 style4 s">Ь</td>
				<td class="column15 style5 s">Э</td>
				<td class="column16 style4 s">Ю</td>
				<td class="column17 style5 s">Я</td>
				<td class="column18 style4 s">А</td>
				<td class="column19 style5 s">Б</td>
				<td class="column20 style4 s">В</td>
				<td class="column21 style5 s">Г</td>
				<td class="column22 style4 s">Д</td>
				<td class="column23 style5 s">Е</td>
				<td class="column24 style4 s">Ё</td>
				<td class="column25 style5 s">Ж</td>
				<td class="column26 style4 s">З</td>
				<td class="column27 style5 s">И</td>
				<td class="column28 style4 s">Й</td>
				<td class="column29 style5 s">К</td>
				<td class="column30 style4 s">Л</td>
				<td class="column31 style5 s">М</td>
				<td class="column32 style4 s">Н</td>
				<td class="column33 style5 s">О</td>
			  </tr>
			  <tr class="row18">
				<td class="column0 style3 s">П</td>
				<td class="column1 style4 s">Р</td>
				<td class="column2 style5 s">С</td>
				<td class="column3 style4 s">Т</td>
				<td class="column4 style5 s">У</td>
				<td class="column5 style4 s">Ф</td>
				<td class="column6 style5 s">Х</td>
				<td class="column7 style4 s">Ц</td>
				<td class="column8 style5 s">Ч</td>
				<td class="column9 style4 s">Ш</td>
				<td class="column10 style5 s">Щ</td>
				<td class="column11 style4 s">Ъ</td>
				<td class="column12 style5 s">Ы</td>
				<td class="column13 style4 s">Ь</td>
				<td class="column14 style5 s">Э</td>
				<td class="column15 style4 s">Ю</td>
				<td class="column16 style5 s">Я</td>
				<td class="column17 style4 s">А</td>
				<td class="column18 style5 s">Б</td>
				<td class="column19 style4 s">В</td>
				<td class="column20 style5 s">Г</td>
				<td class="column21 style4 s">Д</td>
				<td class="column22 style5 s">Е</td>
				<td class="column23 style4 s">Ё</td>
				<td class="column24 style5 s">Ж</td>
				<td class="column25 style4 s">З</td>
				<td class="column26 style5 s">И</td>
				<td class="column27 style4 s">Й</td>
				<td class="column28 style5 s">К</td>
				<td class="column29 style4 s">Л</td>
				<td class="column30 style5 s">М</td>
				<td class="column31 style4 s">Н</td>
				<td class="column32 style5 s">О</td>
				<td class="column33 style4 s">П</td>
			  </tr>
			  <tr class="row19">
				<td class="column0 style3 s">Р</td>
				<td class="column1 style5 s">С</td>
				<td class="column2 style4 s">Т</td>
				<td class="column3 style5 s">У</td>
				<td class="column4 style4 s">Ф</td>
				<td class="column5 style5 s">Х</td>
				<td class="column6 style4 s">Ц</td>
				<td class="column7 style5 s">Ч</td>
				<td class="column8 style4 s">Ш</td>
				<td class="column9 style5 s">Щ</td>
				<td class="column10 style4 s">Ъ</td>
				<td class="column11 style5 s">Ы</td>
				<td class="column12 style4 s">Ь</td>
				<td class="column13 style5 s">Э</td>
				<td class="column14 style4 s">Ю</td>
				<td class="column15 style5 s">Я</td>
				<td class="column16 style4 s">А</td>
				<td class="column17 style5 s">Б</td>
				<td class="column18 style4 s">В</td>
				<td class="column19 style5 s">Г</td>
				<td class="column20 style4 s">Д</td>
				<td class="column21 style5 s">Е</td>
				<td class="column22 style4 s">Ё</td>
				<td class="column23 style5 s">Ж</td>
				<td class="column24 style4 s">З</td>
				<td class="column25 style5 s">И</td>
				<td class="column26 style4 s">Й</td>
				<td class="column27 style5 s">К</td>
				<td class="column28 style4 s">Л</td>
				<td class="column29 style5 s">М</td>
				<td class="column30 style4 s">Н</td>
				<td class="column31 style5 s">О</td>
				<td class="column32 style4 s">П</td>
				<td class="column33 style5 s">Р</td>
			  </tr>
			  <tr class="row20">
				<td class="column0 style3 s">С</td>
				<td class="column1 style4 s">Т</td>
				<td class="column2 style5 s">У</td>
				<td class="column3 style4 s">Ф</td>
				<td class="column4 style5 s">Х</td>
				<td class="column5 style4 s">Ц</td>
				<td class="column6 style5 s">Ч</td>
				<td class="column7 style4 s">Ш</td>
				<td class="column8 style5 s">Щ</td>
				<td class="column9 style4 s">Ъ</td>
				<td class="column10 style5 s">Ы</td>
				<td class="column11 style4 s">Ь</td>
				<td class="column12 style5 s">Э</td>
				<td class="column13 style4 s">Ю</td>
				<td class="column14 style5 s">Я</td>
				<td class="column15 style4 s">А</td>
				<td class="column16 style5 s">Б</td>
				<td class="column17 style4 s">В</td>
				<td class="column18 style5 s">Г</td>
				<td class="column19 style4 s">Д</td>
				<td class="column20 style5 s">Е</td>
				<td class="column21 style4 s">Ё</td>
				<td class="column22 style5 s">Ж</td>
				<td class="column23 style4 s">З</td>
				<td class="column24 style5 s">И</td>
				<td class="column25 style4 s">Й</td>
				<td class="column26 style5 s">К</td>
				<td class="column27 style4 s">Л</td>
				<td class="column28 style5 s">М</td>
				<td class="column29 style4 s">Н</td>
				<td class="column30 style5 s">О</td>
				<td class="column31 style4 s">П</td>
				<td class="column32 style5 s">Р</td>
				<td class="column33 style4 s">С</td>
			  </tr>
			  <tr class="row21">
				<td class="column0 style3 s">Т</td>
				<td class="column1 style5 s">У</td>
				<td class="column2 style4 s">Ф</td>
				<td class="column3 style5 s">Х</td>
				<td class="column4 style4 s">Ц</td>
				<td class="column5 style5 s">Ч</td>
				<td class="column6 style4 s">Ш</td>
				<td class="column7 style5 s">Щ</td>
				<td class="column8 style4 s">Ъ</td>
				<td class="column9 style5 s">Ы</td>
				<td class="column10 style4 s">Ь</td>
				<td class="column11 style5 s">Э</td>
				<td class="column12 style4 s">Ю</td>
				<td class="column13 style5 s">Я</td>
				<td class="column14 style4 s">А</td>
				<td class="column15 style5 s">Б</td>
				<td class="column16 style4 s">В</td>
				<td class="column17 style5 s">Г</td>
				<td class="column18 style4 s">Д</td>
				<td class="column19 style5 s">Е</td>
				<td class="column20 style4 s">Ё</td>
				<td class="column21 style5 s">Ж</td>
				<td class="column22 style4 s">З</td>
				<td class="column23 style5 s">И</td>
				<td class="column24 style4 s">Й</td>
				<td class="column25 style5 s">К</td>
				<td class="column26 style4 s">Л</td>
				<td class="column27 style5 s">М</td>
				<td class="column28 style4 s">Н</td>
				<td class="column29 style5 s">О</td>
				<td class="column30 style4 s">П</td>
				<td class="column31 style5 s">Р</td>
				<td class="column32 style4 s">С</td>
				<td class="column33 style5 s">Т</td>
			  </tr>
			  <tr class="row22">
				<td class="column0 style3 s">У</td>
				<td class="column1 style4 s">Ф</td>
				<td class="column2 style5 s">Х</td>
				<td class="column3 style4 s">Ц</td>
				<td class="column4 style5 s">Ч</td>
				<td class="column5 style4 s">Ш</td>
				<td class="column6 style5 s">Щ</td>
				<td class="column7 style4 s">Ъ</td>
				<td class="column8 style5 s">Ы</td>
				<td class="column9 style4 s">Ь</td>
				<td class="column10 style5 s">Э</td>
				<td class="column11 style4 s">Ю</td>
				<td class="column12 style5 s">Я</td>
				<td class="column13 style4 s">А</td>
				<td class="column14 style5 s">Б</td>
				<td class="column15 style4 s">В</td>
				<td class="column16 style5 s">Г</td>
				<td class="column17 style4 s">Д</td>
				<td class="column18 style5 s">Е</td>
				<td class="column19 style4 s">Ё</td>
				<td class="column20 style5 s">Ж</td>
				<td class="column21 style4 s">З</td>
				<td class="column22 style5 s">И</td>
				<td class="column23 style4 s">Й</td>
				<td class="column24 style5 s">К</td>
				<td class="column25 style4 s">Л</td>
				<td class="column26 style5 s">М</td>
				<td class="column27 style4 s">Н</td>
				<td class="column28 style5 s">О</td>
				<td class="column29 style4 s">П</td>
				<td class="column30 style5 s">Р</td>
				<td class="column31 style4 s">С</td>
				<td class="column32 style5 s">Т</td>
				<td class="column33 style4 s">У</td>
			  </tr>
			  <tr class="row23">
				<td class="column0 style3 s">Ф</td>
				<td class="column1 style5 s">Х</td>
				<td class="column2 style4 s">Ц</td>
				<td class="column3 style5 s">Ч</td>
				<td class="column4 style4 s">Ш</td>
				<td class="column5 style5 s">Щ</td>
				<td class="column6 style4 s">Ъ</td>
				<td class="column7 style5 s">Ы</td>
				<td class="column8 style4 s">Ь</td>
				<td class="column9 style5 s">Э</td>
				<td class="column10 style4 s">Ю</td>
				<td class="column11 style5 s">Я</td>
				<td class="column12 style4 s">А</td>
				<td class="column13 style5 s">Б</td>
				<td class="column14 style4 s">В</td>
				<td class="column15 style5 s">Г</td>
				<td class="column16 style4 s">Д</td>
				<td class="column17 style5 s">Е</td>
				<td class="column18 style4 s">Ё</td>
				<td class="column19 style5 s">Ж</td>
				<td class="column20 style4 s">З</td>
				<td class="column21 style5 s">И</td>
				<td class="column22 style4 s">Й</td>
				<td class="column23 style5 s">К</td>
				<td class="column24 style4 s">Л</td>
				<td class="column25 style5 s">М</td>
				<td class="column26 style4 s">Н</td>
				<td class="column27 style5 s">О</td>
				<td class="column28 style4 s">П</td>
				<td class="column29 style5 s">Р</td>
				<td class="column30 style4 s">С</td>
				<td class="column31 style5 s">Т</td>
				<td class="column32 style4 s">У</td>
				<td class="column33 style5 s">Ф</td>
			  </tr>
			  <tr class="row24">
				<td class="column0 style3 s">Х</td>
				<td class="column1 style4 s">Ц</td>
				<td class="column2 style5 s">Ч</td>
				<td class="column3 style4 s">Ш</td>
				<td class="column4 style5 s">Щ</td>
				<td class="column5 style4 s">Ъ</td>
				<td class="column6 style5 s">Ы</td>
				<td class="column7 style4 s">Ь</td>
				<td class="column8 style5 s">Э</td>
				<td class="column9 style4 s">Ю</td>
				<td class="column10 style5 s">Я</td>
				<td class="column11 style4 s">А</td>
				<td class="column12 style5 s">Б</td>
				<td class="column13 style4 s">В</td>
				<td class="column14 style5 s">Г</td>
				<td class="column15 style4 s">Д</td>
				<td class="column16 style5 s">Е</td>
				<td class="column17 style4 s">Ё</td>
				<td class="column18 style5 s">Ж</td>
				<td class="column19 style4 s">З</td>
				<td class="column20 style5 s">И</td>
				<td class="column21 style4 s">Й</td>
				<td class="column22 style5 s">К</td>
				<td class="column23 style4 s">Л</td>
				<td class="column24 style5 s">М</td>
				<td class="column25 style4 s">Н</td>
				<td class="column26 style5 s">О</td>
				<td class="column27 style4 s">П</td>
				<td class="column28 style5 s">Р</td>
				<td class="column29 style4 s">С</td>
				<td class="column30 style5 s">Т</td>
				<td class="column31 style4 s">У</td>
				<td class="column32 style5 s">Ф</td>
				<td class="column33 style4 s">Х</td>
			  </tr>
			  <tr class="row25">
				<td class="column0 style3 s">Ц</td>
				<td class="column1 style5 s">Ч</td>
				<td class="column2 style4 s">Ш</td>
				<td class="column3 style5 s">Щ</td>
				<td class="column4 style4 s">Ъ</td>
				<td class="column5 style5 s">Ы</td>
				<td class="column6 style4 s">Ь</td>
				<td class="column7 style5 s">Э</td>
				<td class="column8 style4 s">Ю</td>
				<td class="column9 style5 s">Я</td>
				<td class="column10 style4 s">А</td>
				<td class="column11 style5 s">Б</td>
				<td class="column12 style4 s">В</td>
				<td class="column13 style5 s">Г</td>
				<td class="column14 style4 s">Д</td>
				<td class="column15 style5 s">Е</td>
				<td class="column16 style4 s">Ё</td>
				<td class="column17 style5 s">Ж</td>
				<td class="column18 style4 s">З</td>
				<td class="column19 style5 s">И</td>
				<td class="column20 style4 s">Й</td>
				<td class="column21 style5 s">К</td>
				<td class="column22 style4 s">Л</td>
				<td class="column23 style5 s">М</td>
				<td class="column24 style4 s">Н</td>
				<td class="column25 style5 s">О</td>
				<td class="column26 style4 s">П</td>
				<td class="column27 style5 s">Р</td>
				<td class="column28 style4 s">С</td>
				<td class="column29 style5 s">Т</td>
				<td class="column30 style4 s">У</td>
				<td class="column31 style5 s">Ф</td>
				<td class="column32 style4 s">Х</td>
				<td class="column33 style5 s">Ц</td>
			  </tr>
			  <tr class="row26">
				<td class="column0 style3 s">Ч</td>
				<td class="column1 style4 s">Ш</td>
				<td class="column2 style5 s">Щ</td>
				<td class="column3 style4 s">Ъ</td>
				<td class="column4 style5 s">Ы</td>
				<td class="column5 style4 s">Ь</td>
				<td class="column6 style5 s">Э</td>
				<td class="column7 style4 s">Ю</td>
				<td class="column8 style5 s">Я</td>
				<td class="column9 style4 s">А</td>
				<td class="column10 style5 s">Б</td>
				<td class="column11 style4 s">В</td>
				<td class="column12 style5 s">Г</td>
				<td class="column13 style4 s">Д</td>
				<td class="column14 style5 s">Е</td>
				<td class="column15 style4 s">Ё</td>
				<td class="column16 style5 s">Ж</td>
				<td class="column17 style4 s">З</td>
				<td class="column18 style5 s">И</td>
				<td class="column19 style4 s">Й</td>
				<td class="column20 style5 s">К</td>
				<td class="column21 style4 s">Л</td>
				<td class="column22 style5 s">М</td>
				<td class="column23 style4 s">Н</td>
				<td class="column24 style5 s">О</td>
				<td class="column25 style4 s">П</td>
				<td class="column26 style5 s">Р</td>
				<td class="column27 style4 s">С</td>
				<td class="column28 style5 s">Т</td>
				<td class="column29 style4 s">У</td>
				<td class="column30 style5 s">Ф</td>
				<td class="column31 style4 s">Х</td>
				<td class="column32 style5 s">Ц</td>
				<td class="column33 style4 s">Ч</td>
			  </tr>
			  <tr class="row27">
				<td class="column0 style3 s">Ш</td>
				<td class="column1 style5 s">Щ</td>
				<td class="column2 style4 s">Ъ</td>
				<td class="column3 style5 s">Ы</td>
				<td class="column4 style4 s">Ь</td>
				<td class="column5 style5 s">Э</td>
				<td class="column6 style4 s">Ю</td>
				<td class="column7 style5 s">Я</td>
				<td class="column8 style4 s">А</td>
				<td class="column9 style5 s">Б</td>
				<td class="column10 style4 s">В</td>
				<td class="column11 style5 s">Г</td>
				<td class="column12 style4 s">Д</td>
				<td class="column13 style5 s">Е</td>
				<td class="column14 style4 s">Ё</td>
				<td class="column15 style5 s">Ж</td>
				<td class="column16 style4 s">З</td>
				<td class="column17 style5 s">И</td>
				<td class="column18 style4 s">Й</td>
				<td class="column19 style5 s">К</td>
				<td class="column20 style4 s">Л</td>
				<td class="column21 style5 s">М</td>
				<td class="column22 style4 s">Н</td>
				<td class="column23 style5 s">О</td>
				<td class="column24 style4 s">П</td>
				<td class="column25 style5 s">Р</td>
				<td class="column26 style4 s">С</td>
				<td class="column27 style5 s">Т</td>
				<td class="column28 style4 s">У</td>
				<td class="column29 style5 s">Ф</td>
				<td class="column30 style4 s">Х</td>
				<td class="column31 style5 s">Ц</td>
				<td class="column32 style4 s">Ч</td>
				<td class="column33 style5 s">Ш</td>
			  </tr>
			  <tr class="row28">
				<td class="column0 style3 s">Щ</td>
				<td class="column1 style4 s">Ъ</td>
				<td class="column2 style5 s">Ы</td>
				<td class="column3 style4 s">Ь</td>
				<td class="column4 style5 s">Э</td>
				<td class="column5 style4 s">Ю</td>
				<td class="column6 style5 s">Я</td>
				<td class="column7 style4 s">А</td>
				<td class="column8 style5 s">Б</td>
				<td class="column9 style4 s">В</td>
				<td class="column10 style5 s">Г</td>
				<td class="column11 style4 s">Д</td>
				<td class="column12 style5 s">Е</td>
				<td class="column13 style4 s">Ё</td>
				<td class="column14 style5 s">Ж</td>
				<td class="column15 style4 s">З</td>
				<td class="column16 style5 s">И</td>
				<td class="column17 style4 s">Й</td>
				<td class="column18 style5 s">К</td>
				<td class="column19 style4 s">Л</td>
				<td class="column20 style5 s">М</td>
				<td class="column21 style4 s">Н</td>
				<td class="column22 style5 s">О</td>
				<td class="column23 style4 s">П</td>
				<td class="column24 style5 s">Р</td>
				<td class="column25 style4 s">С</td>
				<td class="column26 style5 s">Т</td>
				<td class="column27 style4 s">У</td>
				<td class="column28 style5 s">Ф</td>
				<td class="column29 style4 s">Х</td>
				<td class="column30 style5 s">Ц</td>
				<td class="column31 style4 s">Ч</td>
				<td class="column32 style5 s">Ш</td>
				<td class="column33 style4 s">Щ</td>
			  </tr>
			  <tr class="row29">
				<td class="column0 style3 s">Ъ</td>
				<td class="column1 style5 s">Ы</td>
				<td class="column2 style4 s">Ь</td>
				<td class="column3 style5 s">Э</td>
				<td class="column4 style4 s">Ю</td>
				<td class="column5 style5 s">Я</td>
				<td class="column6 style4 s">А</td>
				<td class="column7 style5 s">Б</td>
				<td class="column8 style4 s">В</td>
				<td class="column9 style5 s">Г</td>
				<td class="column10 style4 s">Д</td>
				<td class="column11 style5 s">Е</td>
				<td class="column12 style4 s">Ё</td>
				<td class="column13 style5 s">Ж</td>
				<td class="column14 style4 s">З</td>
				<td class="column15 style5 s">И</td>
				<td class="column16 style4 s">Й</td>
				<td class="column17 style5 s">К</td>
				<td class="column18 style4 s">Л</td>
				<td class="column19 style5 s">М</td>
				<td class="column20 style4 s">Н</td>
				<td class="column21 style5 s">О</td>
				<td class="column22 style4 s">П</td>
				<td class="column23 style5 s">Р</td>
				<td class="column24 style4 s">С</td>
				<td class="column25 style5 s">Т</td>
				<td class="column26 style4 s">У</td>
				<td class="column27 style5 s">Ф</td>
				<td class="column28 style4 s">Х</td>
				<td class="column29 style5 s">Ц</td>
				<td class="column30 style4 s">Ч</td>
				<td class="column31 style5 s">Ш</td>
				<td class="column32 style4 s">Щ</td>
				<td class="column33 style5 s">Ъ</td>
			  </tr>
			  <tr class="row30">
				<td class="column0 style3 s">Ы</td>
				<td class="column1 style4 s">Ь</td>
				<td class="column2 style5 s">Э</td>
				<td class="column3 style4 s">Ю</td>
				<td class="column4 style5 s">Я</td>
				<td class="column5 style4 s">А</td>
				<td class="column6 style5 s">Б</td>
				<td class="column7 style4 s">В</td>
				<td class="column8 style5 s">Г</td>
				<td class="column9 style4 s">Д</td>
				<td class="column10 style5 s">Е</td>
				<td class="column11 style4 s">Ё</td>
				<td class="column12 style5 s">Ж</td>
				<td class="column13 style4 s">З</td>
				<td class="column14 style5 s">И</td>
				<td class="column15 style4 s">Й</td>
				<td class="column16 style5 s">К</td>
				<td class="column17 style4 s">Л</td>
				<td class="column18 style5 s">М</td>
				<td class="column19 style4 s">Н</td>
				<td class="column20 style5 s">О</td>
				<td class="column21 style4 s">П</td>
				<td class="column22 style5 s">Р</td>
				<td class="column23 style4 s">С</td>
				<td class="column24 style5 s">Т</td>
				<td class="column25 style4 s">У</td>
				<td class="column26 style5 s">Ф</td>
				<td class="column27 style4 s">Х</td>
				<td class="column28 style5 s">Ц</td>
				<td class="column29 style4 s">Ч</td>
				<td class="column30 style5 s">Ш</td>
				<td class="column31 style4 s">Щ</td>
				<td class="column32 style5 s">Ъ</td>
				<td class="column33 style4 s">Ы</td>
			  </tr>
			  <tr class="row31">
				<td class="column0 style3 s">Ь</td>
				<td class="column1 style5 s">Э</td>
				<td class="column2 style4 s">Ю</td>
				<td class="column3 style5 s">Я</td>
				<td class="column4 style4 s">А</td>
				<td class="column5 style5 s">Б</td>
				<td class="column6 style4 s">В</td>
				<td class="column7 style5 s">Г</td>
				<td class="column8 style4 s">Д</td>
				<td class="column9 style5 s">Е</td>
				<td class="column10 style4 s">Ё</td>
				<td class="column11 style5 s">Ж</td>
				<td class="column12 style4 s">З</td>
				<td class="column13 style5 s">И</td>
				<td class="column14 style4 s">Й</td>
				<td class="column15 style5 s">К</td>
				<td class="column16 style4 s">Л</td>
				<td class="column17 style5 s">М</td>
				<td class="column18 style4 s">Н</td>
				<td class="column19 style5 s">О</td>
				<td class="column20 style4 s">П</td>
				<td class="column21 style5 s">Р</td>
				<td class="column22 style4 s">С</td>
				<td class="column23 style5 s">Т</td>
				<td class="column24 style4 s">У</td>
				<td class="column25 style5 s">Ф</td>
				<td class="column26 style4 s">Х</td>
				<td class="column27 style5 s">Ц</td>
				<td class="column28 style4 s">Ч</td>
				<td class="column29 style5 s">Ш</td>
				<td class="column30 style4 s">Щ</td>
				<td class="column31 style5 s">Ъ</td>
				<td class="column32 style4 s">Ы</td>
				<td class="column33 style5 s">Ь</td>
			  </tr>
			  <tr class="row32">
				<td class="column0 style3 s">Э</td>
				<td class="column1 style4 s">Ю</td>
				<td class="column2 style5 s">Я</td>
				<td class="column3 style4 s">А</td>
				<td class="column4 style5 s">Б</td>
				<td class="column5 style4 s">В</td>
				<td class="column6 style5 s">Г</td>
				<td class="column7 style4 s">Д</td>
				<td class="column8 style5 s">Е</td>
				<td class="column9 style4 s">Ё</td>
				<td class="column10 style5 s">Ж</td>
				<td class="column11 style4 s">З</td>
				<td class="column12 style5 s">И</td>
				<td class="column13 style4 s">Й</td>
				<td class="column14 style5 s">К</td>
				<td class="column15 style4 s">Л</td>
				<td class="column16 style5 s">М</td>
				<td class="column17 style4 s">Н</td>
				<td class="column18 style5 s">О</td>
				<td class="column19 style4 s">П</td>
				<td class="column20 style5 s">Р</td>
				<td class="column21 style4 s">С</td>
				<td class="column22 style5 s">Т</td>
				<td class="column23 style4 s">У</td>
				<td class="column24 style5 s">Ф</td>
				<td class="column25 style4 s">Х</td>
				<td class="column26 style5 s">Ц</td>
				<td class="column27 style4 s">Ч</td>
				<td class="column28 style5 s">Ш</td>
				<td class="column29 style4 s">Щ</td>
				<td class="column30 style5 s">Ъ</td>
				<td class="column31 style4 s">Ы</td>
				<td class="column32 style5 s">Ь</td>
				<td class="column33 style4 s">Э</td>
			  </tr>
			  <tr class="row33">
				<td class="column0 style3 s">Ю</td>
				<td class="column1 style5 s">Я</td>
				<td class="column2 style4 s">А</td>
				<td class="column3 style5 s">Б</td>
				<td class="column4 style4 s">В</td>
				<td class="column5 style5 s">Г</td>
				<td class="column6 style4 s">Д</td>
				<td class="column7 style5 s">Е</td>
				<td class="column8 style4 s">Ё</td>
				<td class="column9 style5 s">Ж</td>
				<td class="column10 style4 s">З</td>
				<td class="column11 style5 s">И</td>
				<td class="column12 style4 s">Й</td>
				<td class="column13 style5 s">К</td>
				<td class="column14 style4 s">Л</td>
				<td class="column15 style5 s">М</td>
				<td class="column16 style4 s">Н</td>
				<td class="column17 style5 s">О</td>
				<td class="column18 style4 s">П</td>
				<td class="column19 style5 s">Р</td>
				<td class="column20 style4 s">С</td>
				<td class="column21 style5 s">Т</td>
				<td class="column22 style4 s">У</td>
				<td class="column23 style5 s">Ф</td>
				<td class="column24 style4 s">Х</td>
				<td class="column25 style5 s">Ц</td>
				<td class="column26 style4 s">Ч</td>
				<td class="column27 style5 s">Ш</td>
				<td class="column28 style4 s">Щ</td>
				<td class="column29 style5 s">Ъ</td>
				<td class="column30 style4 s">Ы</td>
				<td class="column31 style5 s">Ь</td>
				<td class="column32 style4 s">Э</td>
				<td class="column33 style5 s">Ю</td>
			  </tr>
			  <tr class="row34">
				<td class="column0 style3 s">Я</td>
				<td class="column1 style4 s">А</td>
				<td class="column2 style5 s">Б</td>
				<td class="column3 style4 s">В</td>
				<td class="column4 style5 s">Г</td>
				<td class="column5 style4 s">Д</td>
				<td class="column6 style5 s">Е</td>
				<td class="column7 style4 s">Ё</td>
				<td class="column8 style5 s">Ж</td>
				<td class="column9 style4 s">З</td>
				<td class="column10 style5 s">И</td>
				<td class="column11 style4 s">Й</td>
				<td class="column12 style5 s">К</td>
				<td class="column13 style4 s">Л</td>
				<td class="column14 style5 s">М</td>
				<td class="column15 style4 s">Н</td>
				<td class="column16 style5 s">О</td>
				<td class="column17 style4 s">П</td>
				<td class="column18 style5 s">Р</td>
				<td class="column19 style4 s">С</td>
				<td class="column20 style5 s">Т</td>
				<td class="column21 style4 s">У</td>
				<td class="column22 style5 s">Ф</td>
				<td class="column23 style4 s">Х</td>
				<td class="column24 style5 s">Ц</td>
				<td class="column25 style4 s">Ч</td>
				<td class="column26 style5 s">Ш</td>
				<td class="column27 style4 s">Щ</td>
				<td class="column28 style5 s">Ъ</td>
				<td class="column29 style4 s">Ы</td>
				<td class="column30 style5 s">Ь</td>
				<td class="column31 style4 s">Э</td>
				<td class="column32 style5 s">Ю</td>
				<td class="column33 style4 s">Я</td>
			</tbody>
		  </table>
	</body>
</html>
	
</details>

Шифр Цезаря - устаревший и небезопасный способ шифрования информации, но он всё ещё используется в некоторых базах данных и компьютерных играх.

Реализация этого метода на языке Python может выглядеть так:

``` Python 
Cyrillic_alphabet = ('А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я') # Кортеж с русским алфавитом 
plain_text = 'Шифр' # Открытый текст 
cipher = '' # Переменная, в которую будет записываться шифротекст
CONST = 6 # Сдвиг 

for char in plain_text: # Перебор каждого символа начального текста
	# Проверяем, является ли символ русской буквой
    if char.upper() in Cyrillic_alphabet:  
        is_upper = (char == char.upper()) # Проверка регистра буквы 
        index = Cyrillic_alphabet.index(char.upper()) # Определяем индекс буквы в кортеже
        new_index = (index + CONST) % len(Cyrillic_alphabet)  # Закольцовка через модуль
        symbol = Cyrillic_alphabet[new_index] 
        cipher += symbol if is_upper else symbol.lower()
    else:
        cipher += char  # Сохраняем символы, не входящие в алфавит

print(cipher)
```

Задание: добавьте для шифра Цезаря обработку латинских букв и цифр.

<details>
	<summary><b>Пример выполненного задания:</b></summary> 

``` Python
Cyrillic_alphabet = ('А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я') # Кортеж с русским алфавитом 
Latin_alphabet = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z') # Кортеж с латинскими буквами
Numbers = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9') # Кортеж с цифрами
plain_text = 'Шифр' # Открытый текст 
cipher = '' # Переменная, в которую будет записываться шифротекст
CONST = 6 # Сдвиг 
alphabets = {
	'cyrillic': Cyrillic_alphabet,
	'latin': Latin_alphabet,
	'numbers': Numbers
} # Словарь алфавитов

# Функция шифрования для заданного алфавита
def CipherFunc(alphabet, char):
	# Проверка наличия символа в алфавите 
	if char.upper() in alphabet: 
		index = alphabet.index(char.upper())
		new_index = (index + CONST) % len(alphabet) # Закольцовка через модуль
		return alphabet[new_index] # Возвращение нового символа
	return None

# Основной цикл шифрования
for char in plain_text:
	is_upper = (char == char.upper())  # Проверка регистра
	encrypted_char = None # Переменная для нового символа
	# Проверяем принадлежность символа к каждому алфавиту
	for alphabet in alphabets.values():
		encrypted_char = CipherFunc(alphabet, char)
		# Остановка цикла если функция вернула символ 
		if encrypted_char:
			break
	# Добавляем зашифрованный символ с учётом регистра или исходный символ, если символа нет в алфавите
	if encrypted_char:
		cipher += encrypted_char if is_upper else encrypted_char.lower()
	else:
		cipher += char

print(cipher)  # Вывод шифротекста
```
</details>

<!-- TOC --><a name="--5"></a>
## Шифр Виженера

Следующий более продвинутый шифр – это шифр Виженера. Смысл этого алгоритма заключается в том, что смещение каждой буквы открытого текста определяется не фиксированным числом, как в шифре Цезаря, а числом, соответствующим позиции буквы ключевого слова в алфавите. Шифр Виженера, чаще всего, демонстрируется в образовательных целях и не используется в целях защиты безопасности. Ключ **повторяется циклически** для шифрования всего текста, если он короче открытого текста, а если длиннее, то обрезается до длинны текста. Начинать нумерацию букв в шифре нужно с **0**.

Напишем номера букв в начальном и ключевом словах:

| Буква нач. слова | Порядковый номер | Буква ключ. слова | Порядковый номер |
| ---------------- | ---------------- | ----------------- | ---------------- |
| К                | 11               | К                 | 11               |
| И                | 9                | У                 | 20               |
| Т                | 19               | Б                 | 1                |

Сложим номера позиций букв начального и ключевого слов, и запишем букву, которая стоит на получившейся позиции:

| Номер буквы нач. слова | Номер буквы ключ. слова | Сумма номеров | Конечная буква |
| ---------------------- | ----------------------- | ------------- | -------------- |
| 11                     | 11                      | 22            | Х              |
| 9                      | 20                      | 29            | Ь              |
| 19                     | 1                       | 20            | У              |

В итоге получили шифротекст: "Хьу"
Так же можно воспользоваться таблицей для получения зашифрованной буквы.

<details>
	<summary><b>Таблица значений</b></summary> 

<html>
  <body>
    <table border="0" cellpadding="0" cellspacing="0" id="sheet0" class="sheet0 gridlines">
        <col class="col0">
        <col class="col1">
        <col class="col2">
        <col class="col3">
        <col class="col4">
        <col class="col5">
        <col class="col6">
        <col class="col7">
        <col class="col8">
        <col class="col9">
        <col class="col10">
        <col class="col11">
        <col class="col12">
        <col class="col13">
        <col class="col14">
        <col class="col15">
        <col class="col16">
        <col class="col17">
        <col class="col18">
        <col class="col19">
        <col class="col20">
        <col class="col21">
        <col class="col22">
        <col class="col23">
        <col class="col24">
        <col class="col25">
        <col class="col26">
        <col class="col27">
        <col class="col28">
        <col class="col29">
        <col class="col30">
        <col class="col31">
        <col class="col32">
        <col class="col33">
        <tbody>
          <tr class="row0">
            <td class="column0 style1 s">Буква ключа / Буква открытого текста</td>
            <td class="column1 style2 s">А</td>
            <td class="column2 style2 s">Б</td>
            <td class="column3 style2 s">В</td>
            <td class="column4 style2 s">Г</td>
            <td class="column5 style2 s">Д</td>
            <td class="column6 style2 s">Е</td>
            <td class="column7 style2 s">Ё</td>
            <td class="column8 style2 s">Ж</td>
            <td class="column9 style2 s">З</td>
            <td class="column10 style2 s">И</td>
            <td class="column11 style2 s">Й</td>
            <td class="column12 style2 s">К</td>
            <td class="column13 style2 s">Л</td>
            <td class="column14 style2 s">М</td>
            <td class="column15 style2 s">Н</td>
            <td class="column16 style2 s">О</td>
            <td class="column17 style2 s">П</td>
            <td class="column18 style2 s">Р</td>
            <td class="column19 style2 s">С</td>
            <td class="column20 style2 s">Т</td>
            <td class="column21 style2 s">У</td>
            <td class="column22 style2 s">Ф</td>
            <td class="column23 style2 s">Х</td>
            <td class="column24 style2 s">Ц</td>
            <td class="column25 style2 s">Ч</td>
            <td class="column26 style2 s">Ш</td>
            <td class="column27 style2 s">Щ</td>
            <td class="column28 style2 s">Ъ</td>
            <td class="column29 style2 s">Ы</td>
            <td class="column30 style2 s">Ь</td>
            <td class="column31 style2 s">Э</td>
            <td class="column32 style2 s">Ю</td>
            <td class="column33 style2 s">Я</td>
          </tr>
          <tr class="row1">
            <td class="column0 style5 s">А</td>
            <td class="column1 style3 s">А</td>
            <td class="column2 style4 s">Б</td>
            <td class="column3 style3 s">В</td>
            <td class="column4 style4 s">Г</td>
            <td class="column5 style3 s">Д</td>
            <td class="column6 style4 s">Е</td>
            <td class="column7 style3 s">Ё</td>
            <td class="column8 style4 s">Ж</td>
            <td class="column9 style3 s">З</td>
            <td class="column10 style4 s">И</td>
            <td class="column11 style3 s">Й</td>
            <td class="column12 style4 s">К</td>
            <td class="column13 style3 s">Л</td>
            <td class="column14 style4 s">М</td>
            <td class="column15 style3 s">Н</td>
            <td class="column16 style4 s">О</td>
            <td class="column17 style3 s">П</td>
            <td class="column18 style4 s">Р</td>
            <td class="column19 style3 s">С</td>
            <td class="column20 style4 s">Т</td>
            <td class="column21 style3 s">У</td>
            <td class="column22 style4 s">Ф</td>
            <td class="column23 style3 s">Х</td>
            <td class="column24 style4 s">Ц</td>
            <td class="column25 style3 s">Ч</td>
            <td class="column26 style4 s">Ш</td>
            <td class="column27 style3 s">Щ</td>
            <td class="column28 style4 s">Ъ</td>
            <td class="column29 style3 s">Ы</td>
            <td class="column30 style4 s">Ь</td>
            <td class="column31 style3 s">Э</td>
            <td class="column32 style4 s">Ю</td>
            <td class="column33 style3 s">Я</td>
          </tr>
          <tr class="row2">
            <td class="column0 style5 s">Б</td>
            <td class="column1 style4 s">Б</td>
            <td class="column2 style3 s">В</td>
            <td class="column3 style4 s">Г</td>
            <td class="column4 style3 s">Д</td>
            <td class="column5 style4 s">Е</td>
            <td class="column6 style3 s">Ё</td>
            <td class="column7 style4 s">Ж</td>
            <td class="column8 style3 s">З</td>
            <td class="column9 style4 s">И</td>
            <td class="column10 style3 s">Й</td>
            <td class="column11 style4 s">К</td>
            <td class="column12 style3 s">Л</td>
            <td class="column13 style4 s">М</td>
            <td class="column14 style3 s">Н</td>
            <td class="column15 style4 s">О</td>
            <td class="column16 style3 s">П</td>
            <td class="column17 style4 s">Р</td>
            <td class="column18 style3 s">С</td>
            <td class="column19 style4 s">Т</td>
            <td class="column20 style3 s">У</td>
            <td class="column21 style4 s">Ф</td>
            <td class="column22 style3 s">Х</td>
            <td class="column23 style4 s">Ц</td>
            <td class="column24 style3 s">Ч</td>
            <td class="column25 style4 s">Ш</td>
            <td class="column26 style3 s">Щ</td>
            <td class="column27 style4 s">Ъ</td>
            <td class="column28 style3 s">Ы</td>
            <td class="column29 style4 s">Ь</td>
            <td class="column30 style3 s">Э</td>
            <td class="column31 style4 s">Ю</td>
            <td class="column32 style3 s">Я</td>
            <td class="column33 style4 s">А</td>
          </tr>
          <tr class="row3">
            <td class="column0 style5 s">В</td>
            <td class="column1 style3 s">В</td>
            <td class="column2 style4 s">Г</td>
            <td class="column3 style3 s">Д</td>
            <td class="column4 style4 s">Е</td>
            <td class="column5 style3 s">Ё</td>
            <td class="column6 style4 s">Ж</td>
            <td class="column7 style3 s">З</td>
            <td class="column8 style4 s">И</td>
            <td class="column9 style3 s">Й</td>
            <td class="column10 style4 s">К</td>
            <td class="column11 style3 s">Л</td>
            <td class="column12 style4 s">М</td>
            <td class="column13 style3 s">Н</td>
            <td class="column14 style4 s">О</td>
            <td class="column15 style3 s">П</td>
            <td class="column16 style4 s">Р</td>
            <td class="column17 style3 s">С</td>
            <td class="column18 style4 s">Т</td>
            <td class="column19 style3 s">У</td>
            <td class="column20 style4 s">Ф</td>
            <td class="column21 style3 s">Х</td>
            <td class="column22 style4 s">Ц</td>
            <td class="column23 style3 s">Ч</td>
            <td class="column24 style4 s">Ш</td>
            <td class="column25 style3 s">Щ</td>
            <td class="column26 style4 s">Ъ</td>
            <td class="column27 style3 s">Ы</td>
            <td class="column28 style4 s">Ь</td>
            <td class="column29 style3 s">Э</td>
            <td class="column30 style4 s">Ю</td>
            <td class="column31 style3 s">Я</td>
            <td class="column32 style4 s">А</td>
            <td class="column33 style3 s">Б</td>
          </tr>
          <tr class="row4">
            <td class="column0 style5 s">Г</td>
            <td class="column1 style4 s">Г</td>
            <td class="column2 style3 s">Д</td>
            <td class="column3 style4 s">Е</td>
            <td class="column4 style3 s">Ё</td>
            <td class="column5 style4 s">Ж</td>
            <td class="column6 style3 s">З</td>
            <td class="column7 style4 s">И</td>
            <td class="column8 style3 s">Й</td>
            <td class="column9 style4 s">К</td>
            <td class="column10 style3 s">Л</td>
            <td class="column11 style4 s">М</td>
            <td class="column12 style3 s">Н</td>
            <td class="column13 style4 s">О</td>
            <td class="column14 style3 s">П</td>
            <td class="column15 style4 s">Р</td>
            <td class="column16 style3 s">С</td>
            <td class="column17 style4 s">Т</td>
            <td class="column18 style3 s">У</td>
            <td class="column19 style4 s">Ф</td>
            <td class="column20 style3 s">Х</td>
            <td class="column21 style4 s">Ц</td>
            <td class="column22 style3 s">Ч</td>
            <td class="column23 style4 s">Ш</td>
            <td class="column24 style3 s">Щ</td>
            <td class="column25 style4 s">Ъ</td>
            <td class="column26 style3 s">Ы</td>
            <td class="column27 style4 s">Ь</td>
            <td class="column28 style3 s">Э</td>
            <td class="column29 style4 s">Ю</td>
            <td class="column30 style3 s">Я</td>
            <td class="column31 style4 s">А</td>
            <td class="column32 style3 s">Б</td>
            <td class="column33 style4 s">В</td>
          </tr>
          <tr class="row5">
            <td class="column0 style5 s">Д</td>
            <td class="column1 style3 s">Д</td>
            <td class="column2 style4 s">Е</td>
            <td class="column3 style3 s">Ё</td>
            <td class="column4 style4 s">Ж</td>
            <td class="column5 style3 s">З</td>
            <td class="column6 style4 s">И</td>
            <td class="column7 style3 s">Й</td>
            <td class="column8 style4 s">К</td>
            <td class="column9 style3 s">Л</td>
            <td class="column10 style4 s">М</td>
            <td class="column11 style3 s">Н</td>
            <td class="column12 style4 s">О</td>
            <td class="column13 style3 s">П</td>
            <td class="column14 style4 s">Р</td>
            <td class="column15 style3 s">С</td>
            <td class="column16 style4 s">Т</td>
            <td class="column17 style3 s">У</td>
            <td class="column18 style4 s">Ф</td>
            <td class="column19 style3 s">Х</td>
            <td class="column20 style4 s">Ц</td>
            <td class="column21 style3 s">Ч</td>
            <td class="column22 style4 s">Ш</td>
            <td class="column23 style3 s">Щ</td>
            <td class="column24 style4 s">Ъ</td>
            <td class="column25 style3 s">Ы</td>
            <td class="column26 style4 s">Ь</td>
            <td class="column27 style3 s">Э</td>
            <td class="column28 style4 s">Ю</td>
            <td class="column29 style3 s">Я</td>
            <td class="column30 style4 s">А</td>
            <td class="column31 style3 s">Б</td>
            <td class="column32 style4 s">В</td>
            <td class="column33 style3 s">Г</td>
          </tr>
          <tr class="row6">
            <td class="column0 style5 s">Е</td>
            <td class="column1 style4 s">Е</td>
            <td class="column2 style3 s">Ё</td>
            <td class="column3 style4 s">Ж</td>
            <td class="column4 style3 s">З</td>
            <td class="column5 style4 s">И</td>
            <td class="column6 style3 s">Й</td>
            <td class="column7 style4 s">К</td>
            <td class="column8 style3 s">Л</td>
            <td class="column9 style4 s">М</td>
            <td class="column10 style3 s">Н</td>
            <td class="column11 style4 s">О</td>
            <td class="column12 style3 s">П</td>
            <td class="column13 style4 s">Р</td>
            <td class="column14 style3 s">С</td>
            <td class="column15 style4 s">Т</td>
            <td class="column16 style3 s">У</td>
            <td class="column17 style4 s">Ф</td>
            <td class="column18 style3 s">Х</td>
            <td class="column19 style4 s">Ц</td>
            <td class="column20 style3 s">Ч</td>
            <td class="column21 style4 s">Ш</td>
            <td class="column22 style3 s">Щ</td>
            <td class="column23 style4 s">Ъ</td>
            <td class="column24 style3 s">Ы</td>
            <td class="column25 style4 s">Ь</td>
            <td class="column26 style3 s">Э</td>
            <td class="column27 style4 s">Ю</td>
            <td class="column28 style3 s">Я</td>
            <td class="column29 style4 s">А</td>
            <td class="column30 style3 s">Б</td>
            <td class="column31 style4 s">В</td>
            <td class="column32 style3 s">Г</td>
            <td class="column33 style4 s">Д</td>
          </tr>
          <tr class="row7">
            <td class="column0 style5 s">Ё</td>
            <td class="column1 style3 s">Ё</td>
            <td class="column2 style4 s">Ж</td>
            <td class="column3 style3 s">З</td>
            <td class="column4 style4 s">И</td>
            <td class="column5 style3 s">Й</td>
            <td class="column6 style4 s">К</td>
            <td class="column7 style3 s">Л</td>
            <td class="column8 style4 s">М</td>
            <td class="column9 style3 s">Н</td>
            <td class="column10 style4 s">О</td>
            <td class="column11 style3 s">П</td>
            <td class="column12 style4 s">Р</td>
            <td class="column13 style3 s">С</td>
            <td class="column14 style4 s">Т</td>
            <td class="column15 style3 s">У</td>
            <td class="column16 style4 s">Ф</td>
            <td class="column17 style3 s">Х</td>
            <td class="column18 style4 s">Ц</td>
            <td class="column19 style3 s">Ч</td>
            <td class="column20 style4 s">Ш</td>
            <td class="column21 style3 s">Щ</td>
            <td class="column22 style4 s">Ъ</td>
            <td class="column23 style3 s">Ы</td>
            <td class="column24 style4 s">Ь</td>
            <td class="column25 style3 s">Э</td>
            <td class="column26 style4 s">Ю</td>
            <td class="column27 style3 s">Я</td>
            <td class="column28 style4 s">А</td>
            <td class="column29 style3 s">Б</td>
            <td class="column30 style4 s">В</td>
            <td class="column31 style3 s">Г</td>
            <td class="column32 style4 s">Д</td>
            <td class="column33 style3 s">Е</td>
          </tr>
          <tr class="row8">
            <td class="column0 style5 s">Ж</td>
            <td class="column1 style4 s">Ж</td>
            <td class="column2 style3 s">З</td>
            <td class="column3 style4 s">И</td>
            <td class="column4 style3 s">Й</td>
            <td class="column5 style4 s">К</td>
            <td class="column6 style3 s">Л</td>
            <td class="column7 style4 s">М</td>
            <td class="column8 style3 s">Н</td>
            <td class="column9 style4 s">О</td>
            <td class="column10 style3 s">П</td>
            <td class="column11 style4 s">Р</td>
            <td class="column12 style3 s">С</td>
            <td class="column13 style4 s">Т</td>
            <td class="column14 style3 s">У</td>
            <td class="column15 style4 s">Ф</td>
            <td class="column16 style3 s">Х</td>
            <td class="column17 style4 s">Ц</td>
            <td class="column18 style3 s">Ч</td>
            <td class="column19 style4 s">Ш</td>
            <td class="column20 style3 s">Щ</td>
            <td class="column21 style4 s">Ъ</td>
            <td class="column22 style3 s">Ы</td>
            <td class="column23 style4 s">Ь</td>
            <td class="column24 style3 s">Э</td>
            <td class="column25 style4 s">Ю</td>
            <td class="column26 style3 s">Я</td>
            <td class="column27 style4 s">А</td>
            <td class="column28 style3 s">Б</td>
            <td class="column29 style4 s">В</td>
            <td class="column30 style3 s">Г</td>
            <td class="column31 style4 s">Д</td>
            <td class="column32 style3 s">Е</td>
            <td class="column33 style4 s">Ё</td>
          </tr>
          <tr class="row9">
            <td class="column0 style5 s">З</td>
            <td class="column1 style3 s">З</td>
            <td class="column2 style4 s">И</td>
            <td class="column3 style3 s">Й</td>
            <td class="column4 style4 s">К</td>
            <td class="column5 style3 s">Л</td>
            <td class="column6 style4 s">М</td>
            <td class="column7 style3 s">Н</td>
            <td class="column8 style4 s">О</td>
            <td class="column9 style3 s">П</td>
            <td class="column10 style4 s">Р</td>
            <td class="column11 style3 s">С</td>
            <td class="column12 style4 s">Т</td>
            <td class="column13 style3 s">У</td>
            <td class="column14 style4 s">Ф</td>
            <td class="column15 style3 s">Х</td>
            <td class="column16 style4 s">Ц</td>
            <td class="column17 style3 s">Ч</td>
            <td class="column18 style4 s">Ш</td>
            <td class="column19 style3 s">Щ</td>
            <td class="column20 style4 s">Ъ</td>
            <td class="column21 style3 s">Ы</td>
            <td class="column22 style4 s">Ь</td>
            <td class="column23 style3 s">Э</td>
            <td class="column24 style4 s">Ю</td>
            <td class="column25 style3 s">Я</td>
            <td class="column26 style4 s">А</td>
            <td class="column27 style3 s">Б</td>
            <td class="column28 style4 s">В</td>
            <td class="column29 style3 s">Г</td>
            <td class="column30 style4 s">Д</td>
            <td class="column31 style3 s">Е</td>
            <td class="column32 style4 s">Ё</td>
            <td class="column33 style3 s">Ж</td>
          </tr>
          <tr class="row10">
            <td class="column0 style5 s">И</td>
            <td class="column1 style4 s">И</td>
            <td class="column2 style3 s">Й</td>
            <td class="column3 style4 s">К</td>
            <td class="column4 style3 s">Л</td>
            <td class="column5 style4 s">М</td>
            <td class="column6 style3 s">Н</td>
            <td class="column7 style4 s">О</td>
            <td class="column8 style3 s">П</td>
            <td class="column9 style4 s">Р</td>
            <td class="column10 style3 s">С</td>
            <td class="column11 style4 s">Т</td>
            <td class="column12 style3 s">У</td>
            <td class="column13 style4 s">Ф</td>
            <td class="column14 style3 s">Х</td>
            <td class="column15 style4 s">Ц</td>
            <td class="column16 style3 s">Ч</td>
            <td class="column17 style4 s">Ш</td>
            <td class="column18 style3 s">Щ</td>
            <td class="column19 style4 s">Ъ</td>
            <td class="column20 style3 s">Ы</td>
            <td class="column21 style4 s">Ь</td>
            <td class="column22 style3 s">Э</td>
            <td class="column23 style4 s">Ю</td>
            <td class="column24 style3 s">Я</td>
            <td class="column25 style4 s">А</td>
            <td class="column26 style3 s">Б</td>
            <td class="column27 style4 s">В</td>
            <td class="column28 style3 s">Г</td>
            <td class="column29 style4 s">Д</td>
            <td class="column30 style3 s">Е</td>
            <td class="column31 style4 s">Ё</td>
            <td class="column32 style3 s">Ж</td>
            <td class="column33 style4 s">З</td>
          </tr>
          <tr class="row11">
            <td class="column0 style5 s">Й</td>
            <td class="column1 style3 s">Й</td>
            <td class="column2 style4 s">К</td>
            <td class="column3 style3 s">Л</td>
            <td class="column4 style4 s">М</td>
            <td class="column5 style3 s">Н</td>
            <td class="column6 style4 s">О</td>
            <td class="column7 style3 s">П</td>
            <td class="column8 style4 s">Р</td>
            <td class="column9 style3 s">С</td>
            <td class="column10 style4 s">Т</td>
            <td class="column11 style3 s">У</td>
            <td class="column12 style4 s">Ф</td>
            <td class="column13 style3 s">Х</td>
            <td class="column14 style4 s">Ц</td>
            <td class="column15 style3 s">Ч</td>
            <td class="column16 style4 s">Ш</td>
            <td class="column17 style3 s">Щ</td>
            <td class="column18 style4 s">Ъ</td>
            <td class="column19 style3 s">Ы</td>
            <td class="column20 style4 s">Ь</td>
            <td class="column21 style3 s">Э</td>
            <td class="column22 style4 s">Ю</td>
            <td class="column23 style3 s">Я</td>
            <td class="column24 style4 s">А</td>
            <td class="column25 style3 s">Б</td>
            <td class="column26 style4 s">В</td>
            <td class="column27 style3 s">Г</td>
            <td class="column28 style4 s">Д</td>
            <td class="column29 style3 s">Е</td>
            <td class="column30 style4 s">Ё</td>
            <td class="column31 style3 s">Ж</td>
            <td class="column32 style4 s">З</td>
            <td class="column33 style3 s">И</td>
          </tr>
          <tr class="row12">
            <td class="column0 style5 s">К</td>
            <td class="column1 style4 s">К</td>
            <td class="column2 style3 s">Л</td>
            <td class="column3 style4 s">М</td>
            <td class="column4 style3 s">Н</td>
            <td class="column5 style4 s">О</td>
            <td class="column6 style3 s">П</td>
            <td class="column7 style4 s">Р</td>
            <td class="column8 style3 s">С</td>
            <td class="column9 style4 s">Т</td>
            <td class="column10 style3 s">У</td>
            <td class="column11 style4 s">Ф</td>
            <td class="column12 style3 s">Х</td>
            <td class="column13 style4 s">Ц</td>
            <td class="column14 style3 s">Ч</td>
            <td class="column15 style4 s">Ш</td>
            <td class="column16 style3 s">Щ</td>
            <td class="column17 style4 s">Ъ</td>
            <td class="column18 style3 s">Ы</td>
            <td class="column19 style4 s">Ь</td>
            <td class="column20 style3 s">Э</td>
            <td class="column21 style4 s">Ю</td>
            <td class="column22 style3 s">Я</td>
            <td class="column23 style4 s">А</td>
            <td class="column24 style3 s">Б</td>
            <td class="column25 style4 s">В</td>
            <td class="column26 style3 s">Г</td>
            <td class="column27 style4 s">Д</td>
            <td class="column28 style3 s">Е</td>
            <td class="column29 style4 s">Ё</td>
            <td class="column30 style3 s">Ж</td>
            <td class="column31 style4 s">З</td>
            <td class="column32 style3 s">И</td>
            <td class="column33 style4 s">Й</td>
          </tr>
          <tr class="row13">
            <td class="column0 style5 s">Л</td>
            <td class="column1 style3 s">Л</td>
            <td class="column2 style4 s">М</td>
            <td class="column3 style3 s">Н</td>
            <td class="column4 style4 s">О</td>
            <td class="column5 style3 s">П</td>
            <td class="column6 style4 s">Р</td>
            <td class="column7 style3 s">С</td>
            <td class="column8 style4 s">Т</td>
            <td class="column9 style3 s">У</td>
            <td class="column10 style4 s">Ф</td>
            <td class="column11 style3 s">Х</td>
            <td class="column12 style4 s">Ц</td>
            <td class="column13 style3 s">Ч</td>
            <td class="column14 style4 s">Ш</td>
            <td class="column15 style3 s">Щ</td>
            <td class="column16 style4 s">Ъ</td>
            <td class="column17 style3 s">Ы</td>
            <td class="column18 style4 s">Ь</td>
            <td class="column19 style3 s">Э</td>
            <td class="column20 style4 s">Ю</td>
            <td class="column21 style3 s">Я</td>
            <td class="column22 style4 s">А</td>
            <td class="column23 style3 s">Б</td>
            <td class="column24 style4 s">В</td>
            <td class="column25 style3 s">Г</td>
            <td class="column26 style4 s">Д</td>
            <td class="column27 style3 s">Е</td>
            <td class="column28 style4 s">Ё</td>
            <td class="column29 style3 s">Ж</td>
            <td class="column30 style4 s">З</td>
            <td class="column31 style3 s">И</td>
            <td class="column32 style4 s">Й</td>
            <td class="column33 style3 s">К</td>
          </tr>
          <tr class="row14">
            <td class="column0 style5 s">М</td>
            <td class="column1 style4 s">М</td>
            <td class="column2 style3 s">Н</td>
            <td class="column3 style4 s">О</td>
            <td class="column4 style3 s">П</td>
            <td class="column5 style4 s">Р</td>
            <td class="column6 style3 s">С</td>
            <td class="column7 style4 s">Т</td>
            <td class="column8 style3 s">У</td>
            <td class="column9 style4 s">Ф</td>
            <td class="column10 style3 s">Х</td>
            <td class="column11 style4 s">Ц</td>
            <td class="column12 style3 s">Ч</td>
            <td class="column13 style4 s">Ш</td>
            <td class="column14 style3 s">Щ</td>
            <td class="column15 style4 s">Ъ</td>
            <td class="column16 style3 s">Ы</td>
            <td class="column17 style4 s">Ь</td>
            <td class="column18 style3 s">Э</td>
            <td class="column19 style4 s">Ю</td>
            <td class="column20 style3 s">Я</td>
            <td class="column21 style4 s">А</td>
            <td class="column22 style3 s">Б</td>
            <td class="column23 style4 s">В</td>
            <td class="column24 style3 s">Г</td>
            <td class="column25 style4 s">Д</td>
            <td class="column26 style3 s">Е</td>
            <td class="column27 style4 s">Ё</td>
            <td class="column28 style3 s">Ж</td>
            <td class="column29 style4 s">З</td>
            <td class="column30 style3 s">И</td>
            <td class="column31 style4 s">Й</td>
            <td class="column32 style3 s">К</td>
            <td class="column33 style4 s">Л</td>
          </tr>
          <tr class="row15">
            <td class="column0 style5 s">Н</td>
            <td class="column1 style3 s">Н</td>
            <td class="column2 style4 s">О</td>
            <td class="column3 style3 s">П</td>
            <td class="column4 style4 s">Р</td>
            <td class="column5 style3 s">С</td>
            <td class="column6 style4 s">Т</td>
            <td class="column7 style3 s">У</td>
            <td class="column8 style4 s">Ф</td>
            <td class="column9 style3 s">Х</td>
            <td class="column10 style4 s">Ц</td>
            <td class="column11 style3 s">Ч</td>
            <td class="column12 style4 s">Ш</td>
            <td class="column13 style3 s">Щ</td>
            <td class="column14 style4 s">Ъ</td>
            <td class="column15 style3 s">Ы</td>
            <td class="column16 style4 s">Ь</td>
            <td class="column17 style3 s">Э</td>
            <td class="column18 style4 s">Ю</td>
            <td class="column19 style3 s">Я</td>
            <td class="column20 style4 s">А</td>
            <td class="column21 style3 s">Б</td>
            <td class="column22 style4 s">В</td>
            <td class="column23 style3 s">Г</td>
            <td class="column24 style4 s">Д</td>
            <td class="column25 style3 s">Е</td>
            <td class="column26 style4 s">Ё</td>
            <td class="column27 style3 s">Ж</td>
            <td class="column28 style4 s">З</td>
            <td class="column29 style3 s">И</td>
            <td class="column30 style4 s">Й</td>
            <td class="column31 style3 s">К</td>
            <td class="column32 style4 s">Л</td>
            <td class="column33 style3 s">М</td>
          </tr>
          <tr class="row16">
            <td class="column0 style5 s">О</td>
            <td class="column1 style4 s">О</td>
            <td class="column2 style3 s">П</td>
            <td class="column3 style4 s">Р</td>
            <td class="column4 style3 s">С</td>
            <td class="column5 style4 s">Т</td>
            <td class="column6 style3 s">У</td>
            <td class="column7 style4 s">Ф</td>
            <td class="column8 style3 s">Х</td>
            <td class="column9 style4 s">Ц</td>
            <td class="column10 style3 s">Ч</td>
            <td class="column11 style4 s">Ш</td>
            <td class="column12 style3 s">Щ</td>
            <td class="column13 style4 s">Ъ</td>
            <td class="column14 style3 s">Ы</td>
            <td class="column15 style4 s">Ь</td>
            <td class="column16 style3 s">Э</td>
            <td class="column17 style4 s">Ю</td>
            <td class="column18 style3 s">Я</td>
            <td class="column19 style4 s">А</td>
            <td class="column20 style3 s">Б</td>
            <td class="column21 style4 s">В</td>
            <td class="column22 style3 s">Г</td>
            <td class="column23 style4 s">Д</td>
            <td class="column24 style3 s">Е</td>
            <td class="column25 style4 s">Ё</td>
            <td class="column26 style3 s">Ж</td>
            <td class="column27 style4 s">З</td>
            <td class="column28 style3 s">И</td>
            <td class="column29 style4 s">Й</td>
            <td class="column30 style3 s">К</td>
            <td class="column31 style4 s">Л</td>
            <td class="column32 style3 s">М</td>
            <td class="column33 style4 s">Н</td>
          </tr>
          <tr class="row17">
            <td class="column0 style5 s">П</td>
            <td class="column1 style3 s">П</td>
            <td class="column2 style4 s">Р</td>
            <td class="column3 style3 s">С</td>
            <td class="column4 style4 s">Т</td>
            <td class="column5 style3 s">У</td>
            <td class="column6 style4 s">Ф</td>
            <td class="column7 style3 s">Х</td>
            <td class="column8 style4 s">Ц</td>
            <td class="column9 style3 s">Ч</td>
            <td class="column10 style4 s">Ш</td>
            <td class="column11 style3 s">Щ</td>
            <td class="column12 style4 s">Ъ</td>
            <td class="column13 style3 s">Ы</td>
            <td class="column14 style4 s">Ь</td>
            <td class="column15 style3 s">Э</td>
            <td class="column16 style4 s">Ю</td>
            <td class="column17 style3 s">Я</td>
            <td class="column18 style4 s">А</td>
            <td class="column19 style3 s">Б</td>
            <td class="column20 style4 s">В</td>
            <td class="column21 style3 s">Г</td>
            <td class="column22 style4 s">Д</td>
            <td class="column23 style3 s">Е</td>
            <td class="column24 style4 s">Ё</td>
            <td class="column25 style3 s">Ж</td>
            <td class="column26 style4 s">З</td>
            <td class="column27 style3 s">И</td>
            <td class="column28 style4 s">Й</td>
            <td class="column29 style3 s">К</td>
            <td class="column30 style4 s">Л</td>
            <td class="column31 style3 s">М</td>
            <td class="column32 style4 s">Н</td>
            <td class="column33 style3 s">О</td>
          </tr>
          <tr class="row18">
            <td class="column0 style5 s">Р</td>
            <td class="column1 style4 s">Р</td>
            <td class="column2 style3 s">С</td>
            <td class="column3 style4 s">Т</td>
            <td class="column4 style3 s">У</td>
            <td class="column5 style4 s">Ф</td>
            <td class="column6 style3 s">Х</td>
            <td class="column7 style4 s">Ц</td>
            <td class="column8 style3 s">Ч</td>
            <td class="column9 style4 s">Ш</td>
            <td class="column10 style3 s">Щ</td>
            <td class="column11 style4 s">Ъ</td>
            <td class="column12 style3 s">Ы</td>
            <td class="column13 style4 s">Ь</td>
            <td class="column14 style3 s">Э</td>
            <td class="column15 style4 s">Ю</td>
            <td class="column16 style3 s">Я</td>
            <td class="column17 style4 s">А</td>
            <td class="column18 style3 s">Б</td>
            <td class="column19 style4 s">В</td>
            <td class="column20 style3 s">Г</td>
            <td class="column21 style4 s">Д</td>
            <td class="column22 style3 s">Е</td>
            <td class="column23 style4 s">Ё</td>
            <td class="column24 style3 s">Ж</td>
            <td class="column25 style4 s">З</td>
            <td class="column26 style3 s">И</td>
            <td class="column27 style4 s">Й</td>
            <td class="column28 style3 s">К</td>
            <td class="column29 style4 s">Л</td>
            <td class="column30 style3 s">М</td>
            <td class="column31 style4 s">Н</td>
            <td class="column32 style3 s">О</td>
            <td class="column33 style4 s">П</td>
          </tr>
          <tr class="row19">
            <td class="column0 style5 s">С</td>
            <td class="column1 style3 s">С</td>
            <td class="column2 style4 s">Т</td>
            <td class="column3 style3 s">У</td>
            <td class="column4 style4 s">Ф</td>
            <td class="column5 style3 s">Х</td>
            <td class="column6 style4 s">Ц</td>
            <td class="column7 style3 s">Ч</td>
            <td class="column8 style4 s">Ш</td>
            <td class="column9 style3 s">Щ</td>
            <td class="column10 style4 s">Ъ</td>
            <td class="column11 style3 s">Ы</td>
            <td class="column12 style4 s">Ь</td>
            <td class="column13 style3 s">Э</td>
            <td class="column14 style4 s">Ю</td>
            <td class="column15 style3 s">Я</td>
            <td class="column16 style4 s">А</td>
            <td class="column17 style3 s">Б</td>
            <td class="column18 style4 s">В</td>
            <td class="column19 style3 s">Г</td>
            <td class="column20 style4 s">Д</td>
            <td class="column21 style3 s">Е</td>
            <td class="column22 style4 s">Ё</td>
            <td class="column23 style3 s">Ж</td>
            <td class="column24 style4 s">З</td>
            <td class="column25 style3 s">И</td>
            <td class="column26 style4 s">Й</td>
            <td class="column27 style3 s">К</td>
            <td class="column28 style4 s">Л</td>
            <td class="column29 style3 s">М</td>
            <td class="column30 style4 s">Н</td>
            <td class="column31 style3 s">О</td>
            <td class="column32 style4 s">П</td>
            <td class="column33 style3 s">Р</td>
          </tr>
          <tr class="row20">
            <td class="column0 style5 s">Т</td>
            <td class="column1 style4 s">Т</td>
            <td class="column2 style3 s">У</td>
            <td class="column3 style4 s">Ф</td>
            <td class="column4 style3 s">Х</td>
            <td class="column5 style4 s">Ц</td>
            <td class="column6 style3 s">Ч</td>
            <td class="column7 style4 s">Ш</td>
            <td class="column8 style3 s">Щ</td>
            <td class="column9 style4 s">Ъ</td>
            <td class="column10 style3 s">Ы</td>
            <td class="column11 style4 s">Ь</td>
            <td class="column12 style3 s">Э</td>
            <td class="column13 style4 s">Ю</td>
            <td class="column14 style3 s">Я</td>
            <td class="column15 style4 s">А</td>
            <td class="column16 style3 s">Б</td>
            <td class="column17 style4 s">В</td>
            <td class="column18 style3 s">Г</td>
            <td class="column19 style4 s">Д</td>
            <td class="column20 style3 s">Е</td>
            <td class="column21 style4 s">Ё</td>
            <td class="column22 style3 s">Ж</td>
            <td class="column23 style4 s">З</td>
            <td class="column24 style3 s">И</td>
            <td class="column25 style4 s">Й</td>
            <td class="column26 style3 s">К</td>
            <td class="column27 style4 s">Л</td>
            <td class="column28 style3 s">М</td>
            <td class="column29 style4 s">Н</td>
            <td class="column30 style3 s">О</td>
            <td class="column31 style4 s">П</td>
            <td class="column32 style3 s">Р</td>
            <td class="column33 style4 s">С</td>
          </tr>
          <tr class="row21">
            <td class="column0 style5 s">У</td>
            <td class="column1 style3 s">У</td>
            <td class="column2 style4 s">Ф</td>
            <td class="column3 style3 s">Х</td>
            <td class="column4 style4 s">Ц</td>
            <td class="column5 style3 s">Ч</td>
            <td class="column6 style4 s">Ш</td>
            <td class="column7 style3 s">Щ</td>
            <td class="column8 style4 s">Ъ</td>
            <td class="column9 style3 s">Ы</td>
            <td class="column10 style4 s">Ь</td>
            <td class="column11 style3 s">Э</td>
            <td class="column12 style4 s">Ю</td>
            <td class="column13 style3 s">Я</td>
            <td class="column14 style4 s">А</td>
            <td class="column15 style3 s">Б</td>
            <td class="column16 style4 s">В</td>
            <td class="column17 style3 s">Г</td>
            <td class="column18 style4 s">Д</td>
            <td class="column19 style3 s">Е</td>
            <td class="column20 style4 s">Ё</td>
            <td class="column21 style3 s">Ж</td>
            <td class="column22 style4 s">З</td>
            <td class="column23 style3 s">И</td>
            <td class="column24 style4 s">Й</td>
            <td class="column25 style3 s">К</td>
            <td class="column26 style4 s">Л</td>
            <td class="column27 style3 s">М</td>
            <td class="column28 style4 s">Н</td>
            <td class="column29 style3 s">О</td>
            <td class="column30 style4 s">П</td>
            <td class="column31 style3 s">Р</td>
            <td class="column32 style4 s">С</td>
            <td class="column33 style3 s">Т</td>
          </tr>
          <tr class="row22">
            <td class="column0 style5 s">Ф</td>
            <td class="column1 style4 s">Ф</td>
            <td class="column2 style3 s">Х</td>
            <td class="column3 style4 s">Ц</td>
            <td class="column4 style3 s">Ч</td>
            <td class="column5 style4 s">Ш</td>
            <td class="column6 style3 s">Щ</td>
            <td class="column7 style4 s">Ъ</td>
            <td class="column8 style3 s">Ы</td>
            <td class="column9 style4 s">Ь</td>
            <td class="column10 style3 s">Э</td>
            <td class="column11 style4 s">Ю</td>
            <td class="column12 style3 s">Я</td>
            <td class="column13 style4 s">А</td>
            <td class="column14 style3 s">Б</td>
            <td class="column15 style4 s">В</td>
            <td class="column16 style3 s">Г</td>
            <td class="column17 style4 s">Д</td>
            <td class="column18 style3 s">Е</td>
            <td class="column19 style4 s">Ё</td>
            <td class="column20 style3 s">Ж</td>
            <td class="column21 style4 s">З</td>
            <td class="column22 style3 s">И</td>
            <td class="column23 style4 s">Й</td>
            <td class="column24 style3 s">К</td>
            <td class="column25 style4 s">Л</td>
            <td class="column26 style3 s">М</td>
            <td class="column27 style4 s">Н</td>
            <td class="column28 style3 s">О</td>
            <td class="column29 style4 s">П</td>
            <td class="column30 style3 s">Р</td>
            <td class="column31 style4 s">С</td>
            <td class="column32 style3 s">Т</td>
            <td class="column33 style4 s">У</td>
          </tr>
          <tr class="row23">
            <td class="column0 style5 s">Х</td>
            <td class="column1 style3 s">Х</td>
            <td class="column2 style4 s">Ц</td>
            <td class="column3 style3 s">Ч</td>
            <td class="column4 style4 s">Ш</td>
            <td class="column5 style3 s">Щ</td>
            <td class="column6 style4 s">Ъ</td>
            <td class="column7 style3 s">Ы</td>
            <td class="column8 style4 s">Ь</td>
            <td class="column9 style3 s">Э</td>
            <td class="column10 style4 s">Ю</td>
            <td class="column11 style3 s">Я</td>
            <td class="column12 style4 s">А</td>
            <td class="column13 style3 s">Б</td>
            <td class="column14 style4 s">В</td>
            <td class="column15 style3 s">Г</td>
            <td class="column16 style4 s">Д</td>
            <td class="column17 style3 s">Е</td>
            <td class="column18 style4 s">Ё</td>
            <td class="column19 style3 s">Ж</td>
            <td class="column20 style4 s">З</td>
            <td class="column21 style3 s">И</td>
            <td class="column22 style4 s">Й</td>
            <td class="column23 style3 s">К</td>
            <td class="column24 style4 s">Л</td>
            <td class="column25 style3 s">М</td>
            <td class="column26 style4 s">Н</td>
            <td class="column27 style3 s">О</td>
            <td class="column28 style4 s">П</td>
            <td class="column29 style3 s">Р</td>
            <td class="column30 style4 s">С</td>
            <td class="column31 style3 s">Т</td>
            <td class="column32 style4 s">У</td>
            <td class="column33 style3 s">Ф</td>
          </tr>
          <tr class="row24">
            <td class="column0 style5 s">Ц</td>
            <td class="column1 style4 s">Ц</td>
            <td class="column2 style3 s">Ч</td>
            <td class="column3 style4 s">Ш</td>
            <td class="column4 style3 s">Щ</td>
            <td class="column5 style4 s">Ъ</td>
            <td class="column6 style3 s">Ы</td>
            <td class="column7 style4 s">Ь</td>
            <td class="column8 style3 s">Э</td>
            <td class="column9 style4 s">Ю</td>
            <td class="column10 style3 s">Я</td>
            <td class="column11 style4 s">А</td>
            <td class="column12 style3 s">Б</td>
            <td class="column13 style4 s">В</td>
            <td class="column14 style3 s">Г</td>
            <td class="column15 style4 s">Д</td>
            <td class="column16 style3 s">Е</td>
            <td class="column17 style4 s">Ё</td>
            <td class="column18 style3 s">Ж</td>
            <td class="column19 style4 s">З</td>
            <td class="column20 style3 s">И</td>
            <td class="column21 style4 s">Й</td>
            <td class="column22 style3 s">К</td>
            <td class="column23 style4 s">Л</td>
            <td class="column24 style3 s">М</td>
            <td class="column25 style4 s">Н</td>
            <td class="column26 style3 s">О</td>
            <td class="column27 style4 s">П</td>
            <td class="column28 style3 s">Р</td>
            <td class="column29 style4 s">С</td>
            <td class="column30 style3 s">Т</td>
            <td class="column31 style4 s">У</td>
            <td class="column32 style3 s">Ф</td>
            <td class="column33 style4 s">Х</td>
          </tr>
          <tr class="row25">
            <td class="column0 style5 s">Ч</td>
            <td class="column1 style3 s">Ч</td>
            <td class="column2 style4 s">Ш</td>
            <td class="column3 style3 s">Щ</td>
            <td class="column4 style4 s">Ъ</td>
            <td class="column5 style3 s">Ы</td>
            <td class="column6 style4 s">Ь</td>
            <td class="column7 style3 s">Э</td>
            <td class="column8 style4 s">Ю</td>
            <td class="column9 style3 s">Я</td>
            <td class="column10 style4 s">А</td>
            <td class="column11 style3 s">Б</td>
            <td class="column12 style4 s">В</td>
            <td class="column13 style3 s">Г</td>
            <td class="column14 style4 s">Д</td>
            <td class="column15 style3 s">Е</td>
            <td class="column16 style4 s">Ё</td>
            <td class="column17 style3 s">Ж</td>
            <td class="column18 style4 s">З</td>
            <td class="column19 style3 s">И</td>
            <td class="column20 style4 s">Й</td>
            <td class="column21 style3 s">К</td>
            <td class="column22 style4 s">Л</td>
            <td class="column23 style3 s">М</td>
            <td class="column24 style4 s">Н</td>
            <td class="column25 style3 s">О</td>
            <td class="column26 style4 s">П</td>
            <td class="column27 style3 s">Р</td>
            <td class="column28 style4 s">С</td>
            <td class="column29 style3 s">Т</td>
            <td class="column30 style4 s">У</td>
            <td class="column31 style3 s">Ф</td>
            <td class="column32 style4 s">Х</td>
            <td class="column33 style3 s">Ц</td>
          </tr>
          <tr class="row26">
            <td class="column0 style5 s">Ш</td>
            <td class="column1 style4 s">Ш</td>
            <td class="column2 style3 s">Щ</td>
            <td class="column3 style4 s">Ъ</td>
            <td class="column4 style3 s">Ы</td>
            <td class="column5 style4 s">Ь</td>
            <td class="column6 style3 s">Э</td>
            <td class="column7 style4 s">Ю</td>
            <td class="column8 style3 s">Я</td>
            <td class="column9 style4 s">А</td>
            <td class="column10 style3 s">Б</td>
            <td class="column11 style4 s">В</td>
            <td class="column12 style3 s">Г</td>
            <td class="column13 style4 s">Д</td>
            <td class="column14 style3 s">Е</td>
            <td class="column15 style4 s">Ё</td>
            <td class="column16 style3 s">Ж</td>
            <td class="column17 style4 s">З</td>
            <td class="column18 style3 s">И</td>
            <td class="column19 style4 s">Й</td>
            <td class="column20 style3 s">К</td>
            <td class="column21 style4 s">Л</td>
            <td class="column22 style3 s">М</td>
            <td class="column23 style4 s">Н</td>
            <td class="column24 style3 s">О</td>
            <td class="column25 style4 s">П</td>
            <td class="column26 style3 s">Р</td>
            <td class="column27 style4 s">С</td>
            <td class="column28 style3 s">Т</td>
            <td class="column29 style4 s">У</td>
            <td class="column30 style3 s">Ф</td>
            <td class="column31 style4 s">Х</td>
            <td class="column32 style3 s">Ц</td>
            <td class="column33 style4 s">Ч</td>
          </tr>
          <tr class="row27">
            <td class="column0 style5 s">Щ</td>
            <td class="column1 style3 s">Щ</td>
            <td class="column2 style4 s">Ъ</td>
            <td class="column3 style3 s">Ы</td>
            <td class="column4 style4 s">Ь</td>
            <td class="column5 style3 s">Э</td>
            <td class="column6 style4 s">Ю</td>
            <td class="column7 style3 s">Я</td>
            <td class="column8 style4 s">А</td>
            <td class="column9 style3 s">Б</td>
            <td class="column10 style4 s">В</td>
            <td class="column11 style3 s">Г</td>
            <td class="column12 style4 s">Д</td>
            <td class="column13 style3 s">Е</td>
            <td class="column14 style4 s">Ё</td>
            <td class="column15 style3 s">Ж</td>
            <td class="column16 style4 s">З</td>
            <td class="column17 style3 s">И</td>
            <td class="column18 style4 s">Й</td>
            <td class="column19 style3 s">К</td>
            <td class="column20 style4 s">Л</td>
            <td class="column21 style3 s">М</td>
            <td class="column22 style4 s">Н</td>
            <td class="column23 style3 s">О</td>
            <td class="column24 style4 s">П</td>
            <td class="column25 style3 s">Р</td>
            <td class="column26 style4 s">С</td>
            <td class="column27 style3 s">Т</td>
            <td class="column28 style4 s">У</td>
            <td class="column29 style3 s">Ф</td>
            <td class="column30 style4 s">Х</td>
            <td class="column31 style3 s">Ц</td>
            <td class="column32 style4 s">Ч</td>
            <td class="column33 style3 s">Ш</td>
          </tr>
          <tr class="row28">
            <td class="column0 style5 s">Ъ</td>
            <td class="column1 style4 s">Ъ</td>
            <td class="column2 style3 s">Ы</td>
            <td class="column3 style4 s">Ь</td>
            <td class="column4 style3 s">Э</td>
            <td class="column5 style4 s">Ю</td>
            <td class="column6 style3 s">Я</td>
            <td class="column7 style4 s">А</td>
            <td class="column8 style3 s">Б</td>
            <td class="column9 style4 s">В</td>
            <td class="column10 style3 s">Г</td>
            <td class="column11 style4 s">Д</td>
            <td class="column12 style3 s">Е</td>
            <td class="column13 style4 s">Ё</td>
            <td class="column14 style3 s">Ж</td>
            <td class="column15 style4 s">З</td>
            <td class="column16 style3 s">И</td>
            <td class="column17 style4 s">Й</td>
            <td class="column18 style3 s">К</td>
            <td class="column19 style4 s">Л</td>
            <td class="column20 style3 s">М</td>
            <td class="column21 style4 s">Н</td>
            <td class="column22 style3 s">О</td>
            <td class="column23 style4 s">П</td>
            <td class="column24 style3 s">Р</td>
            <td class="column25 style4 s">С</td>
            <td class="column26 style3 s">Т</td>
            <td class="column27 style4 s">У</td>
            <td class="column28 style3 s">Ф</td>
            <td class="column29 style4 s">Х</td>
            <td class="column30 style3 s">Ц</td>
            <td class="column31 style4 s">Ч</td>
            <td class="column32 style3 s">Ш</td>
            <td class="column33 style4 s">Щ</td>
          </tr>
          <tr class="row29">
            <td class="column0 style5 s">Ы</td>
            <td class="column1 style3 s">Ы</td>
            <td class="column2 style4 s">Ь</td>
            <td class="column3 style3 s">Э</td>
            <td class="column4 style4 s">Ю</td>
            <td class="column5 style3 s">Я</td>
            <td class="column6 style4 s">А</td>
            <td class="column7 style3 s">Б</td>
            <td class="column8 style4 s">В</td>
            <td class="column9 style3 s">Г</td>
            <td class="column10 style4 s">Д</td>
            <td class="column11 style3 s">Е</td>
            <td class="column12 style4 s">Ё</td>
            <td class="column13 style3 s">Ж</td>
            <td class="column14 style4 s">З</td>
            <td class="column15 style3 s">И</td>
            <td class="column16 style4 s">Й</td>
            <td class="column17 style3 s">К</td>
            <td class="column18 style4 s">Л</td>
            <td class="column19 style3 s">М</td>
            <td class="column20 style4 s">Н</td>
            <td class="column21 style3 s">О</td>
            <td class="column22 style4 s">П</td>
            <td class="column23 style3 s">Р</td>
            <td class="column24 style4 s">С</td>
            <td class="column25 style3 s">Т</td>
            <td class="column26 style4 s">У</td>
            <td class="column27 style3 s">Ф</td>
            <td class="column28 style4 s">Х</td>
            <td class="column29 style3 s">Ц</td>
            <td class="column30 style4 s">Ч</td>
            <td class="column31 style3 s">Ш</td>
            <td class="column32 style4 s">Щ</td>
            <td class="column33 style3 s">Ъ</td>
          </tr>
          <tr class="row30">
            <td class="column0 style5 s">Ь</td>
            <td class="column1 style4 s">Ь</td>
            <td class="column2 style3 s">Э</td>
            <td class="column3 style4 s">Ю</td>
            <td class="column4 style3 s">Я</td>
            <td class="column5 style4 s">А</td>
            <td class="column6 style3 s">Б</td>
            <td class="column7 style4 s">В</td>
            <td class="column8 style3 s">Г</td>
            <td class="column9 style4 s">Д</td>
            <td class="column10 style3 s">Е</td>
            <td class="column11 style4 s">Ё</td>
            <td class="column12 style3 s">Ж</td>
            <td class="column13 style4 s">З</td>
            <td class="column14 style3 s">И</td>
            <td class="column15 style4 s">Й</td>
            <td class="column16 style3 s">К</td>
            <td class="column17 style4 s">Л</td>
            <td class="column18 style3 s">М</td>
            <td class="column19 style4 s">Н</td>
            <td class="column20 style3 s">О</td>
            <td class="column21 style4 s">П</td>
            <td class="column22 style3 s">Р</td>
            <td class="column23 style4 s">С</td>
            <td class="column24 style3 s">Т</td>
            <td class="column25 style4 s">У</td>
            <td class="column26 style3 s">Ф</td>
            <td class="column27 style4 s">Х</td>
            <td class="column28 style3 s">Ц</td>
            <td class="column29 style4 s">Ч</td>
            <td class="column30 style3 s">Ш</td>
            <td class="column31 style4 s">Щ</td>
            <td class="column32 style3 s">Ъ</td>
            <td class="column33 style4 s">Ы</td>
          </tr>
          <tr class="row31">
            <td class="column0 style5 s">Э</td>
            <td class="column1 style3 s">Э</td>
            <td class="column2 style4 s">Ю</td>
            <td class="column3 style3 s">Я</td>
            <td class="column4 style4 s">А</td>
            <td class="column5 style3 s">Б</td>
            <td class="column6 style4 s">В</td>
            <td class="column7 style3 s">Г</td>
            <td class="column8 style4 s">Д</td>
            <td class="column9 style3 s">Е</td>
            <td class="column10 style4 s">Ё</td>
            <td class="column11 style3 s">Ж</td>
            <td class="column12 style4 s">З</td>
            <td class="column13 style3 s">И</td>
            <td class="column14 style4 s">Й</td>
            <td class="column15 style3 s">К</td>
            <td class="column16 style4 s">Л</td>
            <td class="column17 style3 s">М</td>
            <td class="column18 style4 s">Н</td>
            <td class="column19 style3 s">О</td>
            <td class="column20 style4 s">П</td>
            <td class="column21 style3 s">Р</td>
            <td class="column22 style4 s">С</td>
            <td class="column23 style3 s">Т</td>
            <td class="column24 style4 s">У</td>
            <td class="column25 style3 s">Ф</td>
            <td class="column26 style4 s">Х</td>
            <td class="column27 style3 s">Ц</td>
            <td class="column28 style4 s">Ч</td>
            <td class="column29 style3 s">Ш</td>
            <td class="column30 style4 s">Щ</td>
            <td class="column31 style3 s">Ъ</td>
            <td class="column32 style4 s">Ы</td>
            <td class="column33 style3 s">Ь</td>
          </tr>
          <tr class="row32">
            <td class="column0 style5 s">Ю</td>
            <td class="column1 style4 s">Ю</td>
            <td class="column2 style3 s">Я</td>
            <td class="column3 style4 s">А</td>
            <td class="column4 style3 s">Б</td>
            <td class="column5 style4 s">В</td>
            <td class="column6 style3 s">Г</td>
            <td class="column7 style4 s">Д</td>
            <td class="column8 style3 s">Е</td>
            <td class="column9 style4 s">Ё</td>
            <td class="column10 style3 s">Ж</td>
            <td class="column11 style4 s">З</td>
            <td class="column12 style3 s">И</td>
            <td class="column13 style4 s">Й</td>
            <td class="column14 style3 s">К</td>
            <td class="column15 style4 s">Л</td>
            <td class="column16 style3 s">М</td>
            <td class="column17 style4 s">Н</td>
            <td class="column18 style3 s">О</td>
            <td class="column19 style4 s">П</td>
            <td class="column20 style3 s">Р</td>
            <td class="column21 style4 s">С</td>
            <td class="column22 style3 s">Т</td>
            <td class="column23 style4 s">У</td>
            <td class="column24 style3 s">Ф</td>
            <td class="column25 style4 s">Х</td>
            <td class="column26 style3 s">Ц</td>
            <td class="column27 style4 s">Ч</td>
            <td class="column28 style3 s">Ш</td>
            <td class="column29 style4 s">Щ</td>
            <td class="column30 style3 s">Ъ</td>
            <td class="column31 style4 s">Ы</td>
            <td class="column32 style3 s">Ь</td>
            <td class="column33 style4 s">Э</td>
          </tr>
          <tr class="row33">
            <td class="column0 style5 s">Я</td>
            <td class="column1 style3 s">Я</td>
            <td class="column2 style4 s">А</td>
            <td class="column3 style3 s">Б</td>
            <td class="column4 style4 s">В</td>
            <td class="column5 style3 s">Г</td>
            <td class="column6 style4 s">Д</td>
            <td class="column7 style3 s">Е</td>
            <td class="column8 style4 s">Ё</td>
            <td class="column9 style3 s">Ж</td>
            <td class="column10 style4 s">З</td>
            <td class="column11 style3 s">И</td>
            <td class="column12 style4 s">Й</td>
            <td class="column13 style3 s">К</td>
            <td class="column14 style4 s">Л</td>
            <td class="column15 style3 s">М</td>
            <td class="column16 style4 s">Н</td>
            <td class="column17 style3 s">О</td>
            <td class="column18 style4 s">П</td>
            <td class="column19 style3 s">Р</td>
            <td class="column20 style4 s">С</td>
            <td class="column21 style3 s">Т</td>
            <td class="column22 style4 s">У</td>
            <td class="column23 style3 s">Ф</td>
            <td class="column24 style4 s">Х</td>
            <td class="column25 style3 s">Ц</td>
            <td class="column26 style4 s">Ч</td>
            <td class="column27 style3 s">Ш</td>
            <td class="column28 style4 s">Щ</td>
            <td class="column29 style3 s">Ъ</td>
            <td class="column30 style4 s">Ы</td>
            <td class="column31 style3 s">Ь</td>
            <td class="column32 style4 s">Э</td>
            <td class="column33 style3 s">Ю</td>
          </tr>
        </tbody>
    </table>
  </body>
</html>

</details>

Реализация шифра Виженера на языке Python будет следующей:

``` Python
Cyrillic_alphabet = ('А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я') # Кортеж с русским алфавитом 
plain_text = 'Кит' # Открытый текст 
cipher = '' # Переменная, в которую будет записываться шифротекст
key = 'Куб' # Ключ

# Уравниваем длину текста и ключа
if (len(key) < len(plain_text)):
    key += (key * ((len(plain_text) - len(key)) // len(key))) + key[:((len(plain_text) - len(key)) % len(key))]
elif (len(key) > len(plain_text)):
    key = key[:len(plain_text)]

# Перебор каждого символа начального текста
for i in range(len(plain_text)): 
	# Проверяем, является ли символ русской буквой
    if plain_text[i].upper() in Cyrillic_alphabet:  
        is_upper = (plain_text[i] == plain_text[i].upper()) # Проверка регистра буквы 
        index = Cyrillic_alphabet.index(plain_text[i].upper()) # Определяем индекс буквы в кортеже
        index_key = Cyrillic_alphabet.index(key[i].upper()) # Определяем индекс буквы ключа в кортеже
        new_index = (index + index_key) % len(Cyrillic_alphabet)  # Закольцовка через модуль
        symbol = Cyrillic_alphabet[new_index] 
        cipher += symbol if is_upper else symbol.lower()
    else:
        cipher += plain_text[i]  # Сохраняем символы, не входящие в алфавит

print(cipher)
```

Задание: добавьте для шифра Виженера обработку латинских букв и цифр

<details>
	<summary><b>Пример выполненного задания:</b></summary>

``` Python
Cyrillic_alphabet = ('А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я') # Кортеж с русским алфавитом 
Latin_alphabet = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z') # Кортеж с латинскими буквами
Numbers = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9') # Кортеж с цифрами
plain_text = 'Кит12' # Открытый текст 
cipher = '' # Переменная, в которую будет записываться шифротекст
key = 'Cool' # Ключ
alphabets = {
	'cyrillic': Cyrillic_alphabet,
	'latin': Latin_alphabet,
	'numbers': Numbers
} # Словарь алфавитов

# Уравниваем длину текста и ключа
if (len(key) < len(plain_text)):
	key += (key * ((len(plain_text) - len(key)) // len(key))) + key[:((len(plain_text) - len(key)) % len(key))]
elif (len(key) > len(plain_text)):
	key = key[:len(plain_text)]

# Функция шифрования для заданного алфавита
def CipherFunc(alphabet, char, index_key):
	# Проверка наличия символа в алфавите 
	if char.upper() in alphabet: 
		index = alphabet.index(char.upper())
		new_index = (index + index_key) % len(alphabet) # Закольцовка через модуль
		return alphabet[new_index] # Возвращение нового символа
	return None

# Функция определдения индекса ключа
def IndexKey(alphabet, i):
	if key[i].upper() in alphabet:
		index_key = alphabet.index(key[i].upper())
		return index_key
	return None

# Основной цикл шифрования
for i in range(len(plain_text)):
	is_upper = (plain_text[i] == plain_text[i].upper())  # Проверка регистра
	encrypted_char = None # Переменная для нового символа
	# Проверяем принадлежность символа ключа к каждому алфавиту
	for alphabet in alphabets.values():
		index_key = IndexKey(alphabet, i)
		# Остановка цикла если функция вернула символ 
		if index_key:
			break
	# Проверяем принадлежность символа начального текста к каждому алфавиту
	for alphabet in alphabets.values():
		encrypted_char = CipherFunc(alphabet, plain_text[i], index_key)
		# Остановка цикла если функция вернула символ 
		if encrypted_char:
			break
	# Добавляем зашифрованный символ с учётом регистра или исходный символ, если символа нет в алфавите
	if encrypted_char:
		cipher += encrypted_char if is_upper else encrypted_char.lower()
	else:
		cipher += plain_text[i]

print(cipher)
```

</details>

<!-- TOC --><a name="-xor"></a>
## Шифрование с помощью XOR

Алгоритм xor-шифрования – один из самых простых линейных симметричных алгоритмов шифрования. Работа алгоритма заключается в последовательном цикличном кодировании символов входной последовательности с символами шифр-ключа с помощью операции сложения по модулю. Шифр XOR используют в вредоносных программах, старых игровых системах, IoT, но не является основным средством защиты.

``` Python
def xor_encrypt_decrypt(data, key):
    
    # Если ключ и начальные данные - это целочисленные переменные, то используем XOR для чисел
    if isinstance(data, int) and isinstance(key, int):
        return data ^ key

    # Преобразуем данные и ключ в байты, если они строки
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, int):
        data = str(data).encode('utf-8')

    if isinstance(key, str):
        key = key.encode('utf-8')
    elif isinstance(key, int):
        key = str(key).encode('utf-8')
    
    # Подгоняем длину ключа к длине данных
    if (len(key) < len(data)):
        key += (key * ((len(data) - len(key)) // len(key))) + key[:((len(data) - len(key)) % len(key))]
    elif (len(key) > len(data)):
        key = key[:len(data)]

    result = []

    # Применяем XOR к каждому байту
    for d, k in zip(data, key):
        result.append(d ^ k)
    return bytes(result) # Возвращаем значение в виде байт-строки

# Пример использования
data = "21276178"
key = 67

# Шифрование
encrypted = xor_encrypt_decrypt(data, key)
print("Зашифрованные данные:", encrypted.decode('utf-8'))

# Расшифровка
decrypted = xor_encrypt_decrypt(encrypted, key)
print("Расшифрованные данные:", decrypted.decode('utf-8'))

```

<!-- TOC --><a name="-2"></a>
## Заключение
Простые методы шифрования, хоть и не являются безопасными, но всё ещё могут использоваться в современном мире. Так что не стоит их использовать для защиты важных данных, без более безопасных алгоритмов шифрования.

<!-- TOC --><a name="--6"></a>
# Продвинутые методы шифрования

В этой главе будут описаны более продвинутые алгоритмы шифрования данных. Так как на начальном уровне нет смысла углубляться в устройство сложных методов, реализовывать их будем  при помощи библиотеки [pycryptodome](https://pypi.org/project/pycryptodome/). Она проста в использовании и имеет подробную и удобную документацию, найти её в pdf формате можно по [ссылке](https://drive.google.com/file/d/19cLoEclYfpUcbW7UN03UBwZCS2a-64Iy/view?usp=sharing).


<!-- TOC --><a name="des-"></a>
## DES - первый в мире открытый стандарт шифрования данных

Алгоритм DES был разработан компанией IBM и утверждён, как стандарт шифрования США в 1976 году. В его основе лежит сеть Фейстеля с 16 раундами, а длина ключа составляет 56 бит (7 байт). Шифр является блочным и симметричным. Так как шифр блочный, то у него есть размер блок. Он равен 8 байтам (64 бита).
Из-за особенностей библиотеки pycryptodome мы будем использовать ключ в 8 байт (64 бита). Дополнительные 8 бит (1 байт) используют для обеспечения целостности, но сейчас эффективная длина ключа составляет 56 бит. 

Для DES в pycryptodome есть несколько режимов шифрования:

- [MODE_ECB](#MODE_ECB)
- [MODE_CBC](#MODE_CBC)
- [MODE_CFB](#MODE_CFB)
- [MODE_OFB](#MODE_OFB)
- [MODE_CTR](#MODE_CTR)
- [MODE_OPENPGP](#MODE_OPENPGP)
- [MODE_EAX](#MODE_EAX)

<!-- TOC --><a name="aes"></a>
## AES

Алгоритм создан в 1998 году. В 2001 году стал стандартом шифрования в США. В его основе лежит сеть подстановок и перестановок (Substitution-Permutation Network, SPN), что отличает его от сети Фейстеля, использованной в DES. Длина ключа может составлять 128, 192 или 256 бит (16, 24 или 32 байта соответственно), а количество раундов шифрования зависит от длины ключа: 10, 12 или 14 раундов. Шифр является блочным и симметричным, с фиксированным размером блока 128 бит (16 байт).

AES заменил устаревший стандарт DES, который стал уязвимым из-за короткой длины ключа (56 бит). В отличие от DES, AES обеспечивает более высокую безопасность и производительность, что делает его одним из самых надёжных алгоритмов шифрования на сегодняшний день.

Для AES в pycryptodome есть несколько режимов шифрования:

- [MODE_ECB](#MODE_ECB)
- [MODE_CBC](#MODE_CBC)
- [MODE_CFB](#MODE_CFB)
- [MODE_OFB](#MODE_OFB)
- [MODE_CTR](#MODE_CTR)
- [MODE_OPENPGP](#MODE_OPENPGP)
- [MODE_EAX](#MODE_EAX)
- [MODE_CCM](#MODE_CCM)
- [MODE_SIV](#MODE_SIV)
- [MODE_GCM](#MODE_GCM)
- [MODE_OCB](#MODE_OCB)

<!-- TOC --><a name="rsa"></a>
## RSA
RSA — это один из самых известных алгоритмов шифрования с открытым ключом, используемый для обеспечения конфиденциальности (шифрования) и аутентификации (цифровых подписей). Так как RSA - асимметричный алгоритм, то у него имеется открытый и закрытый ключ. 
Для работы с RSA в pycryptodome используется модуль Crypto.PublicKey в котором находится класс RSA. Так же стоит сказать, что, если в симметричных шифрах использовались режимы шифрования, то для асимметричных шифров используется схемы шифрования. Для RSA в используемой нами библиотеке есть 3 схемы:
1. [PKCS#1 OAEP](#OAEP)
2. [PKCS#1 v1.5](#v1.5)
3. [PKCS#1 PSS](#PSS)


<!-- TOC --><a name="--7"></a>
## Введение в библиотеку 

Для установки pycryptodome достаточно иметь предустановленный pip (устанавливается вместе с python) и ввести в терминал/командную строку следующую команду:

```bash
pip install pycryptodome
```

После установки библиотеки, и импорта её в проект можно сразу начинать с ней работать. 
Импорт библиотеки в проект выполняется добавлением в файл исходного кода:

```Python
import Crypto # Импорт всей библиотеки, но обычно не используется, а вместо него экспортируют отдельные пакеты или их модули, как показано ниже

# Первый вариант - импорт всего пакета
import Crypto.Cipher # Импорт пакета Cipher
import Crypto.PublicKey # Импорт пакета PublicKey 

# Второй вариант - испорт ТОЛЬКО нужного модуля из пакета. Например, AES
from Crypto.Cipher import AES

```

Так же для использования блочных шифров (DES и AES) размер текста и шифротекста должен быть кратен размеру блока, так что надо использовать инструменты, которые предоставляются самой библиотекой, а именно **pad** и **unpad**. Инструмент pad позволяет увеличивать  длину данных, до кратной указанному целочисленному значению (например, размер блока алгоритма), заполняя пустое место. Unpad в свою очередь, наоборот, позволяет избавится от заполнения.

`pad(<байт-строка>, <число, которому должна быть кратна байт-строка>)`
`unpad(<байт-строка>, <число, которому байт-строка не была кратна>)`

Использование:

```Python
from Crypto.Util.Padding import pad, unpad # Испорт pad и unpad из Util.Padding
text = b'text'
padding_text = pad(text, 6) # b'text\n\n'
unpadding_text = unpad(padding_text, 6) # b'text'

#example = unpad(padding_text, 5) # ОШИБКА! 
```

Увеличение длинны данных, до размера блока алгоритма:

```Python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

plaintext = b'secret' # 6 байт
print(plaintext) # b'secret'
block_size = AES.block_size # Получение размера блока AES (16 байт)
padding_text = pad(plaintext, block_size)
print(padding_text) # b'secret\n\n\n\n\n\n\n\n\n\n'
```

Ещё один инструмент, который будет использоваться - это функция get_random_bytes.
В качестве аргумента она принимаем целочисленное значение - количество байт, которое необходимо сгенерировать.

```Python
from Crypto.Random import get_random_bytes

byte = get_random_bytes(10) # b'uA\x96\xd2\xd1[?\x17i\x9e' или другая случайная байт-строка 

```


Первое, с чем нужно определится - это какой из алгоритмов вы будете использовать: симметричный или асимметричный, ведь для этих алгоритмов библиотека использует разные пакеты: `Crypto.Cipher` и `Crypto.PublicKey` соответственно.

Вторым шагом надо определится с самим алгоритмом и режимом шифрования. В качестве симметричного алгоритма можно использовать AES. 
Для него доступны следующие режимы: 

- MODE_ECB
- MODE_CBC
- MODE_CFB
- MODE_OFB
- MODE_CTR
- MODE_OPENPGP
- MODE_CCM
- MODE_EAX
- MODE_SIV
- MODE_GCM
- MODE_OCB

Для любого из режимов, мы должны создать экземпляр класса алгоритма шифрования, который в качестве аргумента, обязательно принимает: **ключ** и **режим шифрования**. Так же в качестве аргументов может приниматься:
- **iv** (байты) - вектор инициализации, который будет не предсказуем для злоумышленников, который является байт-строкой, которая **ОДИНАКОВОГО** размер с размером блока. Если iv не передан в виде аргумента, то библиотека создаст случайный. 
- **tag** (байты) - параметр который используется для проверки целостности данных (только для дешифрации)
- **segment_size** (int) - количество БИТ, которое составляет один сегмент, на которые разбивается открытый текст и шифротекст. Должно быть кратно 8 и не должно превышать размер блока. Если не указан, то используется стандартное значение - 8 бит. 
- 1. **nonce** (байты) - это начальное значение, которое комбинируется со счетчиком для создания уникального входного блока. Его длина варьируется от 0 до размера блока -1. Если не указано, то библиотека создает случайное значение длиной, равной половине размеру блока. (ДЛЯ [CTR](#MODE_CTR))
  2. **nonce** (байты) - значение, которое используется однократно. Если не указано, то библиотека создаёт случайное, по размеру блока. **ДОЛЖНО БЫТЬ УНИКАЛЬНЫМ ДЛЯ КАЖДОЙ КОМБИНАЦИИ СООБЩЕНИЯ И КЛЮЧА!** (ДЛЯ [EAX](#MODE_EAX))
  3. **nonce** (байты) - значение одноразового числа. **ДОЛЖНО БЫТЬ УНИКАЛЬНЫМ ДЛЯ КАЖДОЙ КОМБИНАЦИИ СООБЩЕНИЯ И КЛЮЧА!**. Для AES его длина варьируется от 7 до 13 байт. (ДЛЯ [CCM](#MODE_CCM))
- **initial_value** (int/байты) - это начальное значение счетчика для первого блока. Может быть как целым числом, так и байтовой строкой, представляющей то же число в формате big-endian. Если не указано, то используется стандартное значение - 0. 
- **counter** - это пользовательский объект счетчика, созданный с помощью Crypto.Util.Counter.new(). Он позволяет задавать более сложную логику инкремента счетчика, чем простое увеличение на 1. Если не указан, то библиотека автоматически увеличивает счетчик на 1 для каждого блока. (Является более продвинутым инструментом. В примерах использоваться не будет, но больше о нём можно узнать в документации PyCryptodome)
- **mac_len** (int) — длина тега MAC (кода аутентификации сообщения), обеспечивающего проверку целостности и подлинности данных. Для режима EAX значение должно быть не менее 2 и не превышать размер блока шифра. Для режима CCM длина должна быть чётным числом в диапазоне от 4 до 16.

> #### ВАЖНО! В режиме CTR!
> Если счётчик переполнится, то шифрование будет не безопасным. Следует избегать таких ситуаций. Чтобы рассчитать предел счётчика, надо знать nonce.
> 
> **Максимальное значение счётчика (МЗС) = $2^{8(\text{размер блока} - L_{\text{nonce}})} - 1 $** 
> 
> Так как initial_value задаёт начальное значение счётчика, то чтобы не выйти на рамки счётчика так же надо знать максимально возможно его значение.
> 
> **Максимальное значение initial_value = $\text{МЗС} - (\text{кол-во блоков} - 1)$**

Пример:
`Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)`

```
key - переменная с ключом

Crypto.Cipher.AES.MODE_ECB - режим шифрования (вместо "MODE_ECB" может быть любой другой из списка выше).
```



Для шифрования и дешифрования в большинстве режимов используются методы класса encrypt() и decrypt() соответственно, в которые предаются открытый текст и шифротекст соответственно, результатом и там и там будет байт-строка. 
Исключением являются CCM, EAX, GCM, SIV, OCB, которые используют методы encrypt_and_digest() и decrypt_and_verify() для шифрования и дешифрования соответственно. В encrypt_and_digest передаётся открытый текст, результатом является **кортеж**, нулевым элементом которого будет **шифротекст** (байт-строка), а первым - **tag** (байт-строка), который используется для проверки целостности данных, а в decrypt_and_verify шифротекст и tag, который использовался для дешифрования текста, результатом будет байт-строка.

Пример encrypt и decrypt:

```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
text = get_random_bytes(AES.block_size)

# Для шифрования текста
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(text) # Результатом будет байт-строка шифротекста

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_ECB)
decrypted = decipher.decrypt(ciphertext) # Результатом будет байт-строка

```

Пример encrypt_and_digest и decrypt_and_verify:

```Python
from Crypto.Cipher import AES

# Для шифрования
cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
ciphertext = cipher.encrypt_and_digest(text) # Важно знать, что переменная будет кортежем!

# Для дешифрования
decipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
decrypted = decipher.decrypt_and_verify(ciphertext, tag) # Результатом будет байт-строка

```

<!-- TOC --><a name="mode_ecb"></a>
### MODE_ECB

ECB является самым простым режимов шифрования. Для его работы в экземпляр нужно передать только ключ и сам режим шифрования. 

> #### Аргументы
> - **Ключ**
> - **Режим**


Для шифрования и дешифрования ECB используется методы созданного экземпляра класса encrypt и decrypt. 

Пример кода для DES:

```Python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

key = get_random_bytes(DES.key_size)
text = get_random_bytes(DES.block_size)
# Для шифрования текста
cipher = DES.new(key, DES.MODE_ECB)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = DES.new(key, DES.MODE_ECB)
decrypted = decipher.decrypt(ciphertext)
```

Пример кода для AES-128:

```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
text = get_random_bytes(AES.block_size)
# Для шифрования текста
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_ECB)
decrypted = decipher.decrypt(ciphertext)
```

<!-- TOC --><a name="mode_cbc"></a>
### MODE_CBC 

CBC - режим шифрования, при котором перед шифрованием каждый блок открытого текста подвергается XOR-перестановке с предыдущим блоком шифротекста. В качестве аргументов экземпляра класса с режимом CBC, кроме ключа, режима, так же нужно передать iv.

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **iv** - вектор инициализации, который будет не предсказуем для злоумышленников, который является байт-строкой, которая **ОДИНАКОВОГО** размер с размером блока. Если iv не передан в виде аргумента, то библиотека создаст случайный. 

Для шифрования и дешифрования CBC используется методы созданного экземпляра класса encrypt и decrypt. 



Пример кода для DES:

```Python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

iv = get_random_bytes(DES.block_size) # создаём случайные байты, длина которых будет равна длине блока алгоритма.
key = get_random_bytes(DES.key_size)
text = get_random_bytes(DES.block_size)

# Для шифрования текста
cipher = DES.new(key, DES.MODE_CBC, iv=iv)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = DES.new(key, DES.MODE_CBC, iv=iv)
decrypted = decipher.decrypt(ciphertext)
```

Пример кода для AES-128: 

```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

iv = get_random_bytes(AES.block_size) # создаём случайные байты, длина которых будет равна длине блока алгоритма.
key = get_random_bytes(16)
text = get_random_bytes(AES.block_size)

# Для шифрования текста
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = DES.new(key, AES.MODE_CBC, iv=iv)
decrypted = decipher.decrypt(ciphertext)
```

<!-- TOC --><a name="mode_cfb"></a>
### MODE_CFB

CFB - это режим работы, который превращает блочный шифр в потоковый шифр. Каждый
байт открытого текста подвергается операции исключающего ИЛИ (XOR) с байтом, взятым
из ключевого потока: в результате получается шифрованный текст.
Ключевой поток формируется для каждого сегмента отдельно: открытый текст разбивается на сегменты (размером от 1 байта до размера блока). Затем для каждого сегмента ключевой поток генерируется путем шифрования с помощью блочного шифра последнего фрагмента шифрованного текста, созданного на данный момент. Если шифрованного текста пока недостаточно, может использоваться Вектор Инициализации (IV) для дополнения.

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **iv** - вектор инициализации, который будет не предсказуем для злоумышленников, который является байт-строкой, которая **ОДИНАКОВОГО** размер с размером блока. Если iv не передан в виде аргумента, то библиотека создаст случайный. 
> - **segment_size** - количество БИТ, которое составляет один сегмент, на которые разбивается открытый текст и шифротекст. Должно быть кратно 8 и не должно превышать размер блока. Если не указан, то используется стандартное значение 8 бит. 

Пример (упрощенно):
1. **Исходные данные:**
	- Открытый текст: "ABCDEFGH".
	- IV: "12345678".
	- Ключ: "secret!!".
2. **Шаг 1: шифрование "A":**
	- Шифруем IV: encrypt("12345678") → "STUVWXYZ".
	- Первый байт ключевого потока: "S".
	- "A" XOR "S" = "a1".
	- Обновляем регистр: "2345678a1".
3. **Шаг 2: шифрование "B":**
	- Шифруем регистр: encrypt("2345678a1") → например, "T*******".
	- Первый байт ключевого потока: "T".
	- "B" XOR "T" = "b2".
	- Обновляем регистр: "345678a1b2".
4. И так далее для "C", "D", ..., "H".

Для шифрования и дешифрования CFB используется методы созданного экземпляра класса encrypt и decrypt, но так как режим делает блочный шифр поточным, то не надо использовать функции pad() и unpad(). 

Пример кода для DES: 
```Python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

iv = get_random_bytes(DES.block_size) # создаём случайные байты, длина которых будет равна длине блока алгоритма.
key = get_random_bytes(DES.key_size)
text = get_random_bytes(DES.block_size) # можно использовать длину отличную от длины блока, например +1 и не потребуется использовать pad, ведь шифр становится потоковым.

# Для шифрования текста
cipher = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=8) # сегмент кратен 8 и не превышает размер блока. 

#example = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=72) # ОШИБКА! segment_size > DES.block_size * 8  

ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=8)
decrypted = decipher.decrypt(ciphertext)
```

Пример кода для AES-128: 
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

iv = get_random_bytes(AES.block_size) # создаём случайные байты, длина которых будет равна длине блока алгоритма.
key = get_random_bytes(16)
text = get_random_bytes(AES.block_size) # можно использовать длину отличную от длины блока, например +1 и не потребуется использовать pad, ведь шифр становится потоковым.

# Для шифрования текста
cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8) # сегмент кратен 8 и не превышает размер блока. 

#example = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=136) # ОШИБКА! segment_size > AES.block_size * 8  

ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8)
decrypted = decipher.decrypt(ciphertext)
```

<!-- TOC --><a name="mode_ofb"></a>
### MODE_OFB

OFB - это еще один режим, который приводит к созданию потокового шифра. Каждый байт открытого текста подвергается операции исключающего ИЛИ (XOR) с байтом, взятым из ключевого потока: в результате получается шифротекст. Ключевой поток формируется путем рекурсивного шифрования Вектора Инициализации (IV).

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **iv** - вектор инициализации, который будет не предсказуем для злоумышленников, который является байт-строкой, которая **ОДИНАКОВОГО** размер с размером блока. Если iv не передан в виде аргумента, то библиотека создаст случайный. 

Для шифрования и дешифрования OFB используется методы созданного экземпляра класса encrypt и decrypt, но так как режим делает блочный шифр поточным, то не надо использовать функции pad() и unpad(). 

Пример кода для DES:
```Python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

iv = get_random_bytes(DES.block_size) # создаём случайные байты, длина которых будет равна длине блока алгоритма.
key = get_random_bytes(DES.key_size)
text = get_random_bytes(DES.block_size) # можно использовать длину отличную от длины блока, например +1 и не потребуется использовать pad, ведь шифр становится потоковым.

# Для шифрования текста
cipher = DES.new(key, DES.MODE_OFB, iv=iv)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = DES.new(key, DES.MODE_OFB, iv=iv)
decrypted = decipher.decrypt(ciphertext)
```

Пример кода для AES-128:
```Python 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

iv = get_random_bytes(AES.block_size) # создаём случайные байты, длина которых будет равна длине блока алгоритма.
key = get_random_bytes(AES.key_size)
text = get_random_bytes(AES.block_size) # можно использовать длину отличную от длины блока, например +1 и не потребуется использовать pad, ведь шифр становится потоковым.

# Для шифрования текста
cipher = AES.new(key, AES.MODE_OFB, iv=iv)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_OFB, iv=iv)
decrypted = decipher.decrypt(ciphertext)
```

<!-- TOC --><a name="mode_ctr"></a>
### MODE_CTR

Этот режим превращает блочный шифр в потоковый шифр. Каждый байт открытого текста подвергается операции исключающего ИЛИ (XOR) с байтом, взятым из ключевого потока: в результате получается шифрованный текст. Ключевой поток генерируется путем шифрования последовательности блоков счетчика с использованием режима ECB. 

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **nonce** - это начальное значение, которое комбинируется со счетчиком для создания уникального входного блока. Её длина варьируется от 0 до размера блока - 1. Если не указано, то библиотека создает случайное значение длиной, равной половине размеру блока. 
> - **initial_value** - это начальное значение счетчика для первого блока. Может быть как целым числом, так и байтовой строкой, представляющей то же число в формате big-endian. Если не указано, то используется стандартное значение - 0.
> - **counter** - это пользовательский объект счетчика, созданный с помощью Crypto.Util.Counter.new(). Он позволяет задавать более сложную логику инкремента счетчика, чем простое увеличение на 1. Если не указан, то библиотека автоматически увеличивает счетчик на 1 для каждого блока.

> #### ВАЖНО! В режиме CTR!
> Если счётчик переполнится, то шифрование будет не безопасным. Следует избегать таких ситуаций. Чтобы рассчитать предел счётчика, надо знать nonce.
> 
> **Максимальное значение счётчика (МЗС) = $2^{8(\text{размер блока} - L_{\text{nonce}})} - 1 $** 
> 
> Так как initial_value задаёт начальное значение счётчика, то чтобы не выйти на рамки счётчика так же надо знать максимально возможно его значение.
> 
> **Максимальное значение initial_value = $\text{МЗС} - (\text{кол-во блоков} - 1)$**

Пример кода для DES:
```Python
'''
В КОДЕ НЕТ ПРОВЕРКИ НА ВЫХОД ЗА ПРЕДЕЛЫ СЧЁТЧИКА!!! 
'''
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

key = get_random_bytes(DES.key_size)
text = get_random_bytes(DES.block_size) # можно использовать длину отличную от длины блока, например +1 и не потребуется использовать pad, ведь шифр становится потоковым.
nonce = get_random_bytes(DES.block_size - 3) # создаём случайные байты для nonce


# Для шифрования текста
cipher = DES.new(key, DES.MODE_CTR, nonce=nonce, initial_value=None, counter=None)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = DES.new(key, DES.MODE_CTR, nonce=nonce, initial_value=None, counter=None)
decrypted = decipher.decrypt(ciphertext)
```

Пример кода для AES-128-128:
```Python
'''
В КОДЕ НЕТ ПРОВЕРКИ НА ВЫХОД ЗА ПРЕДЕЛЫ СЧЁТЧИКА!!! 
'''
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
text = get_random_bytes(AES.block_size) # можно использовать длину отличную от длины блока, например +1 и не потребуется использовать pad, ведь шифр становится потоковым.
nonce = get_random_bytes(AES.block_size - 3) # создаём случайные байты для nonce


# Для шифрования текста
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=None, counter=None)
ciphertext = cipher.encrypt(text)

# Для дешифрования текста
decipher = AES.new(key, DES.MODE_CTR, nonce=nonce, initial_value=None, counter=None)
decrypted = decipher.decrypt(ciphertext)
```


<!-- TOC --><a name="mode_openpgp"></a>
### MODE_OPENPGP

Вариант [CFB ](#MODE_CFB) с двумя отличиями:

1. Первое обращение к методу encrypt(): При первом вызове метода encrypt() возвращается зашифрованный IV (вектор инициализации), соединённый с первым блоком шифротекста. Это отличается от стандартного поведения, где возвращается только шифротекст. При этом зашифрованный IV имеет длину, равную размеру блока шифра плюс дополнительные 2 байта.
2. IV для шифрования и IV для дешифрования разные. IV для шифрования может быть задан или сгенерирован библиотекой, но IV для дешифрования берётся из данных, после шифрования. 

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **iv** -  вектор инициализации, который будет не предсказуем для злоумышленников, который является байт-строкой, которая **ОДИНАКОВОГО** размер с размером блока. Если iv не передан в виде аргумента, то библиотека создаст случайный. 

Пример кода для DES:
```Python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

FirstIV = get_random_bytes(DES.block_size) # начальный iv, который используется ТОЛЬКО для шифрования
key = get_random_bytes(DES.key_size)
text = get_random_bytes(DES.block_size)
nonce = get_random_bytes(DES.block_size - 3) # создаём случайные байты для nonce

# Для шифрования текста
cipher = DES.new(key, DES.MODE_OPENPGP, iv=FirstIV)
ciphertext = cipher.encrypt(text)

SecondIV = ciphertext[:(DES.block_size + 2)] # Выбираем первые байты, где находиться зашифрованный iv. Его длина - размер блока + 2 
decryptiontext = ciphertext[(DES.block_size + 2):] # Выбираем сам шифротекст без iv

# Для дешифрования текста
decipher = DES.new(key, DES.MODE_OPENPGP, iv=SecondIV) 
decrypted = decipher.decrypt(decryptiontext)
```

Пример кода для AES-128:
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

FirstIV = get_random_bytes(AES.block_size) # начальный iv, который используется ТОЛЬКО для шифрования
key = get_random_bytes(16)
text = get_random_bytes(AES.block_size) # можно использовать длину отличную от длины блока, например +1 и не потребуется использовать pad, ведь шифр становится потоковым.
nonce = get_random_bytes(AES.block_size - 3) # создаём случайные байты для nonce

# Для шифрования текста
cipher = DES.new(key, AES.MODE_OPENPGP, iv=FirstIV)
ciphertext = cipher.encrypt(text)

SecondIV = ciphertext[:(AES.block_size + 2)] # Выбираем первые байты, где находиться зашифрованный iv. Его длина - размер блока + 2 
decryptiontext = ciphertext[(AES.block_size + 2):] # Выбираем сам шифротекст без iv

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_OPENPGP, iv=SecondIV) 
decrypted = decipher.decrypt(decryptiontext)

```

<!-- TOC --><a name="mode_eax"></a>
### MODE_EAX

Современный режим AEAD, разработанный для NIST учеными Белларе, Рогавэем и Вагнером в 2003 году.  
>  AEAD - класс блочных режимов шифрования, при котором часть сообщения шифруется, часть остается открытой, и всё сообщение целиком аутентифицировано.

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **nonce** (байты) - значение, которое используется однократно. Если не указано, то библиотека создаёт случайное, по размеру блока. **ДОЛЖНО БЫТЬ УНИКАЛЬНЫМ ДЛЯ КАЖДОЙ КОМБИНАЦИИ СООБЩЕНИЯ И КЛЮЧА!**
> - **mac_len** (int) - длина тега MAC (код аутентификации сообщения), который используется для проверки целостности и подлинности сообщения. Значение должно быть не менее 2 байт и не превышать размер блока шифра. 

Пример кода для DES:
```Python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

key = get_random_bytes(DES.key_size)
text = get_random_bytes(DES.block_size) 
nonce = get_random_bytes(DES.block_size) # создаём случайные байты для nonce, длина не важна 
mac_len = 4 

# Для шифрования текста
cipher = DES.new(key, DES.MODE_EAX, nonce=nonce, mac_len=mac_len)
ciphertext, tag = cipher.encrypt_and_digest(text) # функция возвращает кортеж, в котором нулевой элемент - шифротекс, а первый - тег (MAC) 

# Для дешифрования текста
decipher = DES.new(key, DES.MODE_EAX, nonce=nonce, mac_len=mac_len) 
decrypted = decipher.decrypt_and_verify(ciphertext, tag)
```

Пример кода для AES-128:
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
text = get_random_bytes(AES.block_size) 
nonce = get_random_bytes(AES.block_size) # создаём случайные байты для nonce, длина не важна 
mac_len = 4 

# Для шифрования текста
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=mac_len)
ciphertext, tag = cipher.encrypt_and_digest(text) # функция возвращает кортеж, в котором нулевой элемент - шифротекс, а первый - тег (MAC) 

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=mac_len) 
decrypted = decipher.decrypt_and_verify(ciphertext, tag)
```

<!-- TOC --><a name="mode_ccm"></a>
### MODE_CCM

CCM — это режим работы для криптографических блочных шифров. Он является алгоритмом аутентифицированного шифрования, предназначенным для обеспечения как аутентификации, так и конфиденциальности. Режим CCM работает только для блочных шифров с длиной блока 128 бит. CCM сочетает в себе CBC, который используется для специальный "подписи" для данных — MAC, и CTR для основного шифрования. На данный момент, в библиотеке pycryptodome CCM поддерживает только AES шифрование.

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **nonce** (байты) — одноразовое значение. **ДОЛЖНО БЫТЬ УНИКАЛЬНЫМ ДЛЯ КАЖДОЙ КОМБИНАЦИИ СООБЩЕНИЯ И КЛЮЧА!**. Для AES его длина варьируется от 7 до 13 байт. Чем длиннее nonce, тем меньше допустимый размер сообщения (с nonce в 13 байт сообщение не может превышать 64 КБ). Если не указано, библиотека создает случайный nonce длиной 11 байт (максимальный размер сообщения составляет 4 ГБ). Расчёт максимальной длины сообщения происходит так:
>> **Максимальный размер сообщения = $2^{8\text{(15 - N)}} - 1$ байт (N - длина nonce)**
> Пример:  
>> N = 12 
>>**Максимальный размер сообщения** = $2^{8\text{(15 - 12)}} - 1 = 2^{24} - 1 = 16,777,215$ байт
> - **mac_len** (int) – длина тега MAC (кода аутентификации сообщения), обеспечивающего проверку целостности и подлинности данных. Для режима CCM длина должна быть чётным числом в диапазоне от 4 до 16.
> - **msg_len** (int) – это параметр, который указывает длину сообщения, подлежащего шифрованию или расшифрованию. В режиме CCM эта информация необходима для корректной работы алгоритма, который сочетает шифрование с аутентификацией. В стандартах RFC3610 и NIST SP 800-38C требуют указания длины сообщения.
> - **assoc_len** (int) – предварительное объявление длины ассоциированных данных. Если не указано, будет происходить дополнительное буферирование внутри.
>> Ассоциированные данные – это данные, которые не шифруются, но аутентифицируются вместе с зашифрованным сообщением. Они включаются в процесс проверки целостности и подлинности, чтобы убедиться, что ни шифрованная часть, ни эти дополнительные данные не были изменены. Обычно представляют собой заголовки. 

Пример кода для AES-128:
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
len_nonce = 8 # длина nonce от 7 до 13 байт.
nonce = get_random_bytes(len_nonce) # создаём случайные байты для nonce
text = get_random_bytes(AES.block_size)
mac_len = 4 # длина MAC от 4 до 16, должно быть чётным числом!
header = b"header" # Ассоциированные данные

# Для шифрования текста
cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mac_len, msg_len=len(text), assoc_len=len(header))
cipher.update(header) # добавление ассоциированных данных
ciphertext, tag = cipher.encrypt_and_digest(text) # функция возвращает кортеж, в котором нулевой элемент - шифротекс, а первый - тег (MAC)

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mac_len, msg_len=len(ciphertext), assoc_len=len(header)) 
decipher.update(header) # добавление ассоциированных данных
decrypted = decipher.decrypt_and_verify(ciphertext, tag)
```

<!-- TOC --><a name="mode_siv"></a>
### MODE_SIV
SIV (Synthetic Initialization Vector) работает только с шифрами размер блока, которых равен 128 битам. Хотя SIV менее эффективен, чем другие режимы, он устойчив к неправильному использованию nonce: случайное повторное использование nonce не ставит под угрозу безопасность, как это происходит с CCM или GCM. 

> На самом деле, работа без nonce не является ошибкой как таковой: шифр просто становится детерминированным. 
> Другими словами, сообщение всегда зашифровывается в один и тот же шифротекст.

> #### Аргументы
> - **Ключ**. Длина ключа должна быть в два раза больше, чем обычно. Например, 32 байта для AES-128.
> - **Режим**
> - **nonce** (байты) — одноразовое значение. **ДОЛЖНО БЫТЬ УНИКАЛЬНЫМ ДЛЯ КАЖДОЙ КОМБИНАЦИИ СООБЩЕНИЯ И КЛЮЧА!**. В стандарте RFC 5297 установлено, что случайный nonce должен иметь длину НЕ МЕНЕЕ 128 бит (16 байт). Если отсутствует, шифрование будет детерминированным.

Пример кода для AES-128:
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16 * 2) # Длина ключа в два раза больше
nonce = get_random_bytes(16) # создаём случайные байты для nonce
text = get_random_bytes(AES.block_size)

# Для шифрования текста
cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(text) # функция возвращает кортеж, в котором нулевой элемент - шифротекс, а первый - тег (MAC)

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_SIV, nonce=nonce) 
decrypted = decipher.decrypt_and_verify(ciphertext, tag)
```

<!-- TOC --><a name="mode_gcm"></a>
### MODE_GCM
GCM работает только с шифрами, размер блока которых равен 128 бит. Он сочетает в себе преимущества режима счётчика (CTR) для шифрования и хэш-функции в поле Галуа для проверки целостности данных.

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **nonce** (байты) — одноразовое значение. **ДОЛЖНО БЫТЬ УНИКАЛЬНЫМ ДЛЯ КАЖДОЙ КОМБИНАЦИИ СООБЩЕНИЯ И КЛЮЧА!**. В стандарте NIST SP 800-38D рекомендовано использовать длину nonce в 12 байт (96 бит). Если отсутствует, библиотека создает случайный nonce (длиной 16 байт для AES).
> - **mac_len** (int) – длина тега MAC (кода аутентификации сообщения), обеспечивающего проверку целостности и подлинности данных. Длина должна быть диапазоне от 4 до 16. По умолчанию 16.

Пример кода для AES-128:

```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
nonce = get_random_bytes(12) # создаём случайные байты для nonce
text = get_random_bytes(AES.block_size)
mac_len = 7

# Для шифрования текста
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
ciphertext, tag = cipher.encrypt_and_digest(text) # функция возвращает кортеж, в котором нулевой элемент - шифротекс, а первый - тег (MAC)

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len) 
decrypted = decipher.decrypt_and_verify(ciphertext, tag)
```


<!-- TOC --><a name="mode_ocb"></a>
### MODE_OCB
OCB — это режим работы блочного шифра, который одновременно обеспечивает как конфиденциальность, так и аутентификацию данных. Работает только с шифрами, размер блока которых равен 128 бит. 
Существует несколько версий OCB:
- OCB1 - первая версия, обеспечивающая базовую аутентифицированную шифровк
- OCB2 - улучшенная версия, добавляющая поддержку дополнительных аутентифицируемых данных (AEAD), то есть данных, которые не шифруются, но проверяются на подлинность. Однако в 2019 году OCB2 был признан небезопасным из-за уязвимостей.
- OCB3 - последняя и наиболее совершенная версия, устраняющая недостатки OCB2, с изменённым способом вычисления смещений и небольшими улучшениями производительности. OCB3 считается безопасным и используется в стандарте RFC 7253. 
В pycryptodome реализован OCB3. 

> #### Аргументы
> - **Ключ**
> - **Режим**
> - **nonce** (байты) – одноразовое значение. **ДОЛЖНО БЫТЬ УНИКАЛЬНЫМ ДЛЯ КАЖДОЙ КОМБИНАЦИИ СООБЩЕНИЯ И КЛЮЧА!**. Длина nonce может быть от 1 до 15 байт. Если отсутствует, библиотека создаст случайный nonce длиной 15 байт. 
> - **mac_len** (int) – длина тега MAC. От 8 до 16 для AES. Если отсутствует, то по умолчанию используется 16.

> #### ВАЖНО!
> Если вы шифруете или дешифруете несколько фрагментов, то в конце вы ДОЛЖНЫ вызвать encrypt или decrypt без параметров! 
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

data = [b'chunk1', b'chunk2', b'chunk3'] # фрагменты для шифра
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_OCB)
ciphertext = b''
for chunk in data:
    ciphertext += cipher.encrypt(chunk) # шифрование каждого фрагмента
ciphertext += cipher.encrypt() # ЗАВЕРШЕНИЕ ШИФРОВАНИЯ ВЫЗОВОМ пустого encrypt 
tag = cipher.digest()
```

Пример кода для AES-128 (для разового шифрования и дешифрования):
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
nonce = get_random_bytes(12) # создаём случайные байты для nonce
text = get_random_bytes(AES.block_size)
mac_len = 16

# Для шифрования текста
cipher = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=mac_len)
ciphertext, tag = cipher.encrypt_and_digest(text) # функция возвращает кортеж, в котором нулевой элемент - шифротекс, а первый - тег (MAC)

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=mac_len) 
decrypted = decipher.decrypt_and_verify(ciphertext, tag)
```

Пример кода для AES-128 (для шифрования и дешифрования фрагментами):
```Python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
nonce = get_random_bytes(12) # создаём случайные байты для nonce
data = [get_random_bytes(4), get_random_bytes(4), get_random_bytes(4)] # Список с фрагментами для шифра
mac_len = 16 

cipher = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=mac_len)
ciphertext = b''
# Шифрование каждого фрагмента
for chunk in data:
    ciphertext += cipher.encrypt(chunk)
ciphertext += cipher.encrypt() # ЗАВЕРШЕНИЕ ШИФРОВАНИЯ ВЫЗОВОМ пустого encrypt 
tag = cipher.digest() # получение MAC

# Для дешифрования текста
decipher = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=mac_len)
chunk_length = len(ciphertext) // 2 # Разбитие на два фрагмента, но можно разбить и на 4, и на 3
remainder = len(ciphertext) % 2 # Узнаём остаток, если он остался
start = 0 # Откуда начинается разбитие 
plaintext = b'' # Строка для записи результатов
for i in range(2):
    end = start + chunk_length + (1 if i < remainder else 0) 
    plaintext += decipher.decrypt(ciphertext[start:end])
    start = end 
plaintext += decipher.decrypt() # ЗАВЕРШЕНИЕ ДЕШИФРОВАНИЯ ВЫЗОВОМ пустого decrypt
decipher.verify(tag) # верификация
```
<!-- TOC --><a name="oaep"></a>
### OAEP
PKCS#1 OAEP — это современная схема заполнения, которая добавляет случайность и структуру к сообщению перед шифрованием. Это делает RSA более устойчивым к атакам, связанным с предсказуемостью данных. Используется для шифрования небольших объемов данных, например, симметричных ключей или хэшей.

У OAPE есть свои ограничения:
1. Максимальный размер данных для сообщения  = `(Длина модуля RSA (в байтах) − 2) − (2 × Размер вывода хэш-функции (в байтах))`
По умолчанию в pycryptodome используется хэш-функция SHA-1, вывод которой равен 20 байт (160 бит). Так же можно использовать другие хэш-функции, например, SHA-256 (32 байта (256 бит)), SHA-384 (48 байт (384 бит)), SHA-512 (64 байта (512 бит)). 
В коде кэш-функция передаётся как аргумент при создании экземпляра класса PKCS1_OAEP:
```Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256)
```

Пример кода на для RSA:
```Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Получатель генерирует ключи и экспортирует открытый ключ
receiver_key = RSA.generate(2048)
receiver_public_key = receiver_key.publickey()

# Отправитель импортирует открытый ключ и шифрует сообщение
message = b"message"
sender_cipher = PKCS1_OAEP.new(receiver_public_key)
try:
    ciphertext = sender_cipher.encrypt(message)
except ValueError as e:
    print(e)

# Получатель расшифровывает сообщение с помощью своего закрытого ключа
receiver_decipher = PKCS1_OAEP.new(receiver_key)
plaintext = receiver_decipher.decrypt(ciphertext)
```
<!-- TOC --><a name="v15"></a>
### v1.5
PKCS#1 v1.5 - старая, но все еще надежная схема цифровой подписи на основе RSA, но лучше его не использовать. Может использоваться в двух вариантах:
1. Для шифрования
2. Цифровая подпись

Для шифрования у PKCS#1 v1.5 есть свои ограничения:
1. Максимальная длина текста = k − 11 байт, где k — длина модуля в байтах.
2. При вызове decrypt(), первым аргументом нужно передавать зашифрованный текст, а вторым то, чему будет равна переменная в случае неудачного дешифрования.

Для создание цифровой подписи у PKCS#1 v1.5 так же есть свои ограничения, которые связаны только с используемой хэш-функцией. Например для SHA-256 эта длина составляет $2^{64} - 1$ байт. Длина зависит от того, какой длины данные поддерживает хэш-функция.

Пример кода для шифрования:
```Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Генерация ключа
key = RSA.generate(2048)
public_key = key.publickey()

# Шифрование
message = b"secret"
cipher = PKCS1_v1_5.new(public_key)
ciphertext = cipher.encrypt(message)

# Дешифрование
decipher = PKCS1_v1_5.new(key)
plaintext = decipher.decrypt(ciphertext, "Error!") # вторым аргументом передаётся, то, чему будет равна переменная в случае неудачного дешифрования.
```

Пример кода для цифровой подписи:
```Python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Генерация ключа
key = RSA.generate(2048)
public_key = key.publickey()

# Подпись
message = b"Test" #данные для подписи
hash_obj = SHA256.new(message)
signer = pkcs1_15.new(key)
signature = signer.sign(hash_obj)

# Проверка
verifier = pkcs1_15.new(public_key)
try:
    verifier.verify(hash_obj, signature)
    print("Подпись верна")
except ValueError:
    print("Подпись неверна")
```

<!-- TOC --><a name="pss"></a>
### PSS
PKCS#1 PSS — это более безопасная схема подписи, которая добавляет случайность, что делает её устойчивой к атакам, в отличие от PKCS#1 v1.5. Рекомендуется для цифровых подписей в современных приложениях.
Для создание цифровой подписи у PKCS#1 PSS так же есть свои ограничения, которые связаны только с используемой хэш-функцией. Например для SHA-256 эта длина составляет $2^{64} - 1$ байт. Длина зависит от того, какой длины данные поддерживает хэш-функция.

Пример кода:
```Python
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
message = b"Test"
hash_obj = SHA256.new(message)
# Подпись
signer = pss.new(key) # Создаём объект подписи PSS, используя закрытый ключ RSA
signature = signer.sign(hash_obj) # Подписываем хэш сообщения с помощью закрытого ключа.
# Проверка
verifier = pss.new(key.publickey())
try:
    verifier.verify(hash_obj, signature)
    print("Подпись верна")
except ValueError:
    print("Подпись неверна")
```

<!-- TOC --><a name="--8"></a>
# Частые ошибки

В этом разделе мы рассмотрим наиболее распространенные ошибки, которые допускают начинающие при работе с шифрами.

<!-- TOC --><a name="--9"></a>
## Симметричные шифры
Симметричные шифры используют только один ключ. Ошибки, которые возможно допустить:
1. **Использование слабых ключей**
	- Использование ключей меньшей длины, чем требует алгоритм, например, 64 бита для AES, хотя минимальный ключ - 128 бит.
	- Генерация слишком простых ключей
2. **Неправильное хранение ключей**
	- Хранение ключей в открытом виде в коде или конфигурационных файлах. 
	- Отсутствие защиты ключей при их хранении.
3. **Неправильное использование режимов шифрования**
	- Использование простых режимов, как ECB режима, который не обеспечивает достаточной безопасности для большинства приложений.
	- Неправильная инициализация вектора инициализации (IV) в режимах, требующих его (например, CBC, CFB), что может привести к потери безопасности.
4. **Отсутствие аутентификации**
	- Не использование режимов шифрования, которые обеспечивают аутентификацию (например, GCM, CCM), что может позволить злоумышленнику изменять шифротекст без обнаружения.
5. **Повторное использование nonce или IV в режимах, где они должны быть уникальными для каждой операции шифрования (например, CTR, GCM).**

<!-- TOC --><a name="--10"></a>
## Асимметричные шифры
1. **Неправильное хранение закрытых ключей**
	- Хранение закрытых ключей в незащищенном виде или в доступных для посторонних местах.
	- Передача закрытых ключей по незащищенным каналам.
2. **Использование слабых параметров генерации ключей**
	- Генерация ключей с недостаточной длиной (например, использование 1024-битных ключей для RSA, когда рекомендуется как минимум 2048 бит).
	- Использование устаревших или небезопасных алгоритмов для генерации ключей.
3. **Неправильный выбор алгоритмов**
	- Шифрование больших объемов данных с помощью асимметричных шифров, что неэффективно и медленно. Асимметричные шифры следует использовать для шифрования симметричных ключей или для цифровых подписей.

<!-- TOC --><a name="--11"></a>
## Общие ошибки
1. Неправильная инициализация объектов шифрования или пропуск важных параметров.
2. Попытка реализовать собственные криптографические алгоритмы вместо использования проверенных и стандартизированных решений. 
3. Неправильное представление о том, что шифрование само по себе обеспечивает полную безопасность, без учета других аспектов, таких как аутентификация и целостность данных.
4. Отказ от тестирования на правильность шифрования и дешифрования.
5. Игнорирование обновлений библиотек и языка программирования

<!-- TOC --><a name="--12"></a>
## Как избежать ошибок
- Генерируйте ключи с достаточной безопасностью и подходящей длиной для выбранного алгоритма.
- Используйте безопасные хранилища ключей и избегайте хранения ключей в открытом виде.
- Используйте режимы, которые обеспечивают как конфиденциальность, так и аутентификацию, такие как GCM или CCM.
- Регулярно обновляйте библиотеки до последних версий.
- Проводите тщательное тестирование шифрования и дешифрования, чтобы убедиться в правильности работы вашей программы.