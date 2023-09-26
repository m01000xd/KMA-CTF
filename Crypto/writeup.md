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
101000, 1011000, 111000, 1010101, 1011000, 110110 ('**(X8UX6**' ), và 4 bit cuối: 1001000, 1000110, 1000110, 1111101 ( '**HFF}**' ).

Giờ ta đã cố định được đầu và cuối, nhưng phần giữa có nhiều trường hợp hoán vị các bit 7 và bit 6 cho nhau, ta không thể cố định được.

Nhưng có vài thứ ta có thể rút ra được từ flag_encode:

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/e5414c79-cb63-478b-84d7-f50c5623bae7)

Độ dài của flag_encode là 212, mà chúng ta cần phải chia flag_encode thành các nhóm kí tự 7 bit và 6 bit, mà flag của chúng ta có 32 kí tự. Vậy, ta sẽ có hệ phương trình:
    7x + 6y = 212
     x +  y = 32

Ta rút ra x = 20, y = 12. Vậy flag_encode của chúng ta sẽ chia thành 20 kí tự có độ dài 7 bit và 12 kí tự có độ dài 12. Mặt khác, ta lại xác định được thêm 1 vài bit cố định ở trước đó: '**(**'(6-bit), '**X**'(7-bit), '**8**'(6-bit), '**U**'(7-bit), '**X**'(7-bit), '**6**'(6-bit), '**H**'(7-bit), '**F**'(7-bit), '**F**'(7-bit), vậy giờ ta còn lại 18 kí tự, 9 kí tự dài 7 bit, 9 kí tự dài 6 bit.
Ta để ý 1 chút ở dãy bit của flag_encode:

![image](https://github.com/m01000xd/KMA-CTF/assets/122852491/85d0aa10-f17d-496b-90b8-729e0f3b930e)

Ở đoạn bit này, ta thấy có 1 dãy 6 số 0 và 1 số 1 đứng trước đó, dù cho có bao nhiêu cách chia flag_encode đi nữa, thì đây chắc chắn 
luôn là kí tự 7-bit(1000000) ('***@***'), vì như đã nói ở trên, không có cách nào thỏa mãn để tách thành 2 kí tự, vì số 0 lúc đó luôn luôn
đứng đầu(trái với chứng minh).

Ta còn lại 18 kí tự, với dải bit có độ dài 117. 


Phần tiếp theo là đoạn code tìm flag:

```python
import itertools
from hashlib import md5




##Vì đã biết có bit 1000000, ta sẽ từ bit 1000000 chia dải bit thành 2 nửa, nửa đầu từ bit 1000000 trở về trước và nửa cuối là ngược lại.

nua_dau = '1001011100101110000111010110101111000101111001111110'
nua_cuoi = '1000111100011101101101111010101111111001100011111011110100'

flag_hash = '16ab78b0c0654e663d7e2e22ac0a9b7a'
flag_encode = '10010111001101100000111110111010001011000111000101010110110001101101001011100101110000111010110101111000101111001111110100000010001111000111011011011110101011111110011000111110111101001001000100011010001101111101'

## Nửa đầu có độ dài 52 kí tự, nửa sau có độ dài 58 kí tự. Với cách giải hệ pt tìm số nhóm kí tự dài 7 bit và 6 bit ở trên, ta lần lượt
## xác định được:

## Nửa đầu có 4 kí tự dài 7 bit và 4 kí tự dài 6 bit
## Nửa sau có 4 kí tự dài 7 bit và 5 kí tự dài 6 bit

## Ở đây, ta nghĩ đến việc tạo 1 cách xếp bất kì các kí tự 7 bit và 6 bit. Sau đó ta sẽ dùng itertools để tìm tất cả các tổ hợp các cách
## sắp xếp các kí tự 7 bit và 6 bit ở 2 nửa:

first_part = [7] * 4 + [6] * 4
second_part = [7] * 4 + [6] * 5

to_hop1 = set(itertools.permutations(first_part))
to_hop2 = set(itertools.permutations(second_part))

## Sau đó sẽ tạo 2 mảng cho mỗi nửa, duyệt đến từng cách xếp của mỗi tổ hợp của mỗi nửa, dùng string slice chia thành các bit 7 và bit 6, sau đó append vào mảng:
mang1 = []
mang2 = []


for i in to_hop1:
    index = 0
    groups = []
    for length in i:
        if index + length <= len(nua_dau):
            group = nua_dau[index:index + length]
            if group[0] == '0':
                break     ## Vì bit đầu tiên của mỗi kí tự luôn là bit 1, cho nên nếu có kí tự nào có bit đầu là bit 0, ta sẽ break.
            groups.append(chr(int(group,2)))
            index += length
    if len(groups) == 8:
        mang1.append(groups) ## Do ở trên, nếu có kí tự có bit 0 đầu thì break, mà nửa đầu gồm 4 + 4 = 8 kí tự, nếu có groups đủ 8 kí tự ## thì chắc chắn cách chia đó hợp lệ vì các bit đầu của mỗi kí tự luôn là bit 1.

## Làm tương tự với mảng 2

for i in to_hop2:
    index = 0
    groups = []
    for length in i:
        if index + length <= len(nua_cuoi):
            group = nua_cuoi[index:index + length]
            if group[0] == '0':
                break
            groups.append(chr(int(group,2))) ## Append vào mảng kí tự tương ứng với mỗi bit
            index += length
    if len(groups) == 9:
        mang2.append(groups)

## Join các kí tự đơn lẻ vửa append vào mảng lại thành 1 xâu
mang1 = [''.join(i) for i in mang1]        
mang2 = [''.join(i) for i in mang2]
## itertools.product() để nối tất cả các xâu trong mang1 lần lượt tương ứng với tất cả các xâu trong mảng 2. Vì @ ở giữa nên ta chèn
## thêm @ giữa mang1, mang2:

combinations = ['KMA{(X8UX6' + ''.join(i) + 'HFF}' for i  in list(itertools.product(mang1,'@', mang2))]
## Ta đã được các xâu hoàn chỉnh, giờ ta sẽ đem hash và so với flag_hash để được flag:
flag = ''.join([i for i in combinations if md5(i.encode()).hexdigest() == flag_hash])
print(flag)
```

**Flag:** ***KMA{(X8UX6K%0uWE9>@#1m^W<1=tHFF}***








