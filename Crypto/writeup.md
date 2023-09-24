![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/d1c64cef-b049-4c29-807b-c3c576c3af7d)


Đề bài cho đoạn flag bị hash(flag_hash) và flag khi bị encode sang nhị phân(flag_encode):

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/638248f1-53a3-46f2-991e-c30c375ba8fe)

Ta thấy rằng, flag của chúng ta gồm 32 kí tự:

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/6cdc06a0-2159-43f0-b4de-e0b295c8c481)

Ngoài 5 kí tự "KMA{" và "}" thì còn 27 kí tự được tạo bằng cách lấy random trong string.printable[:-6]: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

Thêm nữa, flag_encode được encode qua hàm encode:

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/95382f33-3ac1-4288-9256-d6cbda93178e)

Với mỗi chữ cái trong flag, ta đổi nó sang thứ tự trong bảng mã Unicode rồi lấy nhị phân, sau đó bỏ đi tiền tố 0b và viết sát lại với nhau, ta được flag_encode.

Chạy chương trình, lấy 1 flag bất kì:

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/6e5f61f2-874e-4fd0-9927-114d546a2e63)

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/7a9e3de9-9982-45d7-84b2-3e6ab4ca7591)

Để ý khi giữ nguyên tiền tố 0b, bit ngay sau đó phải bit 1, không bao giờ là bit 0. Mặt khác, khi bỏ tiền tố 0b, chỉ có hoặc là 7 bit hoặc là 6 bit.

Vì vậy, nhìn vào flag_encode,mặc dù 7 bit và 6 bit có thể đứng ở nhiều vị trí khác nhau , nhưng ta có thể xác định được 1 vài bit cố định: 1001011('**K**'), 1001101('**M**'), 1000001('**A'**), 1111011('**{**'),
101000, 1011000, 111000, 1010101, 1011000, 110110 ('**(X8UX6**' ), và 4 bit cuối: 1001000, 1000110, 1000110, 1111101 ( '**HFF**' ).

Giờ ta đã cố định được đầu và cuối, nhưng phần giữa có nhiều trường hợp hoán vị các bit 7 và bit 6 cho nhau, ta không thể cố định được.

Dù vậy, ta thấy rằng, phần giữa cũng được tạo ra bời string.printable[:-6], ta nghĩ đến việc duyệt 1 vòng for qua các phần tử trong string.printable[:-6], rồi cộng từng chữ cái của nó vào flag,
sau đó, kiểm tra xem flag bây giờ được encode qua hàm  encode() có trùng khớp với flag_encode bây giờ không, nếu có thì in chữ cái đó ra. Mỗi lần như vậy, vì có khi thì là bit 7 , khi thì là bit 6,
nên chúng ta sẽ thử tất cả trường hợp dẫn đến flag ban đầu, sau đó ta sẽ hash flag đó đem đi so với flag_hash xem có trùng khớp không thì chính là flag của chúng ta:

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/ae7dd74d-0a69-4f7f-8231-b4ac58112685)

Sau nhiều lần thử, ta được flag: 'KMA{(X8UX6K%0uWE9>@#1m^W<1=tHFF}'.
flag_hash đượcc tạo ra bằng: flag_hash = md5(flag.encode()).hexdigest(). Đề đã cho flag_hash của flag ban đầu, giờ đem đi so:

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/9fd7c812-c19a-45f9-9e54-c5c238603036)

Kết quả trả về True.

**Flag:** ***KMA{(X8UX6K%0uWE9>@#1m^W<1=tHFF}***








