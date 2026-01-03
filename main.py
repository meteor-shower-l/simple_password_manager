# 迭代点：
# 1.read_jsonl的异常处理

# user_info结构:[{'username':用户名,'encrypted_main_password':主密码,},...]
# user_encrypted_password结构:[{'weburl':网址,'username':用户名,'password':密码},...]

import os
import json
import getpass
import string
import secrets
from pathlib import Path
import base64
import hashlib

class PasswordManager:

    # 哈希函数
    # 调用hashlib库完成哈希加密，用于储存用户主密码以及用户登录时的验证
    def hash_process(self,password):
        result = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return result

    # 文件路径构建函数
    # 使用pathlib构建路径，避免使用绝对路径,从而确保程序的可移植性
    def path(self,file_name):
        script_dir = Path(__file__).resolve().parent
        return script_dir / file_name

    # jsonl文件读取函数
    # 用于从jsonl文件中读入字典列表，若文件不存在，则返回空列表
    def read_jsonl(self,file_path):
        try:
            with open(file_path,'r',encoding='utf-8') as f:
                info_dic_list = [] # 临时用户信息字典列表
                num =0
                for line in f: # jsonl文件中，每行是一个用户信息
                    cleaned_line = line.strip()
                    if not cleaned_line :
                        continue
                    info_dict = json.loads(cleaned_line)
                    info_dic_list.append(info_dict)
                    num +=1
                print(f'载入成功，共读取到{num}条记录')
                return info_dic_list
        except:
            print('载入成功，共读取到0条记录')
            return []

    # 判断键是否在字典列表函数
    # 输入为一个字符串与一个字典列表
    # 判断字符串是否是字典列表中某个元素的值，并返回其位置
    def get_index_by_value_in_dict_list(self,given_value,dict_list):
        result = None
        for i in range(0,len(dict_list)):
            if given_value in ((dict_list[i]).values()):
                result =  i
                break
            else:
                pass
        return result

    # 构造函数
    def __init__(self):
        # 载入用户信息，用于登录时验证
        self.USER_INFO_PATH = self.path("user_info.jsonl")
        print('开始载入用户信息')
        self.user_info = self.read_jsonl(self.USER_INFO_PATH)
        print('载入用户信息完成')
        # 用户主密码、用户加密密码本路径、用户加密密码本在登录时载入，在类创建时置空
        self.user_encrypted_password_path = None
        self.user_encrypted_password = None
        self.user_main_password = None
        self.user_log_stae = False

    # 登录函数，用于完成用户登录，也可以切换账号
    # 在此函数中，完成用户主密码的赋值与加密密码本的读入
    def log_in(self):
        given_username = input("请输入用户名")
        given_userpassword = getpass.getpass("请输入用户密码")
        index = self.get_index_by_value_in_dict_list(given_username,self.user_info)
        if index is not None:
            if  self.user_info[index]['encrypted_main_password']== self.hash_process(given_userpassword): # 若匹配成功
                self.user_main_password = given_userpassword # 将用户输入的密码储存为密码(明文)
                self.user_encrypted_password_path = self.path(f'{given_username}_password.jsonl')
                self.user_encrypted_password = self.read_jsonl(self.user_encrypted_password_path) # 读取文件中的密码至内存
                self.user_log_stae = True
                print('登录成功')
            else:
                print('登录失败,用户名或密码有误')
        else: 
            print('登录失败,用户名或密码有误')

    # 新增用户函数
    # 使用getpass防止密码在屏幕可以见,使用while True循环确保两次密码相同
    # 更新内存中储存的用户列表
    def user_add(self):
        given_username = input('请输入用户名')
        # 先判断用户是否存在
        # 若存在，则提示并直接退出
        if self.get_index_by_value_in_dict_list(given_username,self.user_info) != None:
            print('用户已存在')
        # 若不存在，则提示用户输入密码
        else:
            while True:
                given_password_1 = getpass.getpass('请输入密码')
                given_password_2 = getpass.getpass('请再次输出密码以确认')
                if given_password_1 == given_password_2:
                    break
                else:
                    print('两次输入的密码不同，请重新输入')
            info_dict = {"username":given_username,"encrypted_main_password":self.hash_process(given_password_1)}
            # 写入jsonl(直接使用a模式即可)
            with open(self.USER_INFO_PATH,'a',encoding='utf-8') as f:
                f.write(json.dumps(info_dict)+'\n')
            self.user_info.append(info_dict)
            print(f'成功创建新用户')

    # 修改用户主密码函数
    # 更新内存中储存的用户列表
    # 由于网站密码的加密依赖于主密码，因此该过程中需要对各网站密码进行解密并使用新主密码重新加密并写入
    # 通过重新写入更新user_info.jsonl，存在IO频繁问题,需要迭代完善
    def user_change_main_password(self):
        given_username = input('请输入要修改密码的用户名')
        index=self.get_index_by_value_in_dict_list(given_username,self.user_info)
        if index is None:
            print('用户不存在，无法修改密码')
        else:
            given_userpassword = getpass.getpass('请输入原密码')
            if self.hash_process(given_userpassword) != self.user_info[index]['encrypted_main_password']:
                print('原始密码错误，请确认原密码后再修改')
            else:
                while True:
                    given_password_1 = getpass.getpass('请输入密码')
                    given_password_2 = getpass.getpass('请再次输出密码以确认')
                    if given_password_1 == given_password_2:
                        break
                    else:
                        print('两次输入的密码不同，请重新输入')

                # 暂存各个网站原密码，在主密码更改后，用于更新加密后的密码
                init_password = []
                for item in self.user_encrypted_password:
                    init_password.append(self.total_decrypt(item['password']))

                # 更新主密码
                self.user_main_password = given_password_1

                # 更新user_info
                # jsonl写入(使用w模式覆盖原记录)
                self.user_info[index]['encrypted_main_password'] = self.hash_process(given_password_1)
                with open(self.USER_INFO_PATH,'w',encoding='utf-8') as f:
                    for item in self.user_info:
                        f.write(json.dumps(item)+'\n')

                # 更新user_encrypted_password
                for i in range(len(self.user_encrypted_password)):
                    self.user_encrypted_password[i]['password'] = self.total_encrypt(init_password[i])
                with open(self.user_encrypted_password_path,'w',encoding='utf-8') as f:
                    for item in self.user_encrypted_password:
                        f.write(json.dumps(item)+'\n')
                print(f'成功修改用户{given_username}的密码')

    # 删除用户函数
    # 更新内存中储存的用户列表
    # 通过重新写入更新user_info.jsonl，存在IO频繁问题,需要迭代完善
    def user_delete(self):
        given_username = input('请输入要删除的用户')
        index=self.get_index_by_value_in_dict_list(given_username,self.user_info)
        if  index is None:
            print('用户不存在')
        else:
            given_userpassword = getpass.getpass('请输入原密码')
            if self.hash_process(given_userpassword) != self.user_info[index]['encrypted_main_password']:
                print('密码错误，请确认密码后再修改')
            else:
                del self.user_info[index]
                # jsonl写入(使用w模式覆盖原记录)
                with open(self.USER_INFO_PATH,'w',encoding='utf-8') as f:
                    for item in self.user_info:
                        f.write(json.dumps(item)+'\n')
                # 删除用户的密码文件
                self.user_encrypted_password_path.unlink() #可以增加异常处理
                print(f'成功删除用户{given_username}')

    # 网址展示函数
    def show_weburl(self):
        print('目前已管理密码的网站网址如下:')
        for i in range(0,len(self.user_encrypted_password)):
            print(f'{i+1}.',end='')
            print(self.user_encrypted_password[i]['weburl'])
    
    # 账号密码打印函数
    def show_account_and_password(self,index):
        if index not in range(1,len(self.user_encrypted_password)+1):
            print("请输入范围内的值")
        else:
            print(f"{self.user_encrypted_password[index-1]['weburl']}的账号密码如下:")
            print(f"账号:{self.user_encrypted_password[index-1]['username']}")
            print(f"密码:{self.total_decrypt(self.user_encrypted_password[index-1]['password'])}")

    # 新增账号密码函数
    # 使用getpass防止密码在屏幕可以见,使用while True循环确保两次密码相同
    # 更新内存中储存的用户密码列表
    # 直接更新user_password.jsonl文件
    def password_add(self):
        given_weburl = input('请输入需要添加的网址')
        index = self.get_index_by_value_in_dict_list(given_weburl,self.user_encrypted_password)
        if index is not None:
            print(f'网站{given_weburl}账号密码已存在')
        else:
            given_username = input('请输入用户名')
            while True:
                given_password_1 = getpass.getpass('请输入密码')
                given_password_2 = getpass.getpass('请再次输入密码以确认')
                if given_password_1 == given_password_2:
                    break
            weburl_username_password ={'weburl':given_weburl,
                                    'username':given_username,
                                    'password':self.total_encrypt(given_password_1)}
            with open (self.user_encrypted_password_path,'a',encoding='utf-8') as f:
                f.write(json.dumps(weburl_username_password)+'\n')
            self.user_encrypted_password.append(weburl_username_password)
            print(f'成功创建{given_weburl}网站的账号密码')
    
    # 修改网站密码函数
    # 使用getpass防止密码在屏幕可以见,使用while True循环确保两次密码相同
    # 更新内存中储存的用户密码列表
    # 通过重新写入更新user_info.jsonl，存在IO频繁问题,需要迭代完善
    def password_change_password(self):
        given_weburl = input('请输入要修改密码的网址')
        index = self.get_index_by_value_in_dict_list(given_weburl,self.user_encrypted_password)
        if index is None:
            print(f'不存在网址{given_weburl}的账号密码')
        else:
            while True:
                given_password_1 = getpass.getpass('请输入密码')
                given_password_2 = getpass.getpass('请再次输出密码以确认')
                if given_password_1 == given_password_2:
                    break
                else:
                    print('两次输入的密码不同，请重新输入')
            self.user_encrypted_password[index]['password'] = self.total_encrypt(given_password_1)
            # jsonl写入函数(使用w模式覆盖原记录)
            with open (self.user_encrypted_password_path,'w',encoding='utf-8') as f:
                for item in self.user_encrypted_password:
                    f.write(json.dumps(item)+'\n')
            print(f'已成功修改{given_weburl}网站的密码')

    # 删除网站密码函数
    # 使用getpass防止密码在屏幕可以见
    # 更新内存中储存的用户密码列表
    # 通过重新写入更新user_info.jsonl，存在IO频繁问题,需要迭代完善
    def password_delete(self):
        given_weburl = input('请输入要删除密码的网址')
        index = self.get_index_by_value_in_dict_list(given_weburl,self.user_encrypted_password)
        if index is None:
            print(f'不存在网址为{given_weburl}的账号密码')
        else:
            given_password = getpass.getpass('请输入您的主密码,以完成身份认证')
            if given_password != self.user_main_password:
                print('密码错误，请确认密码后再修改')
            else:
                del self.user_encrypted_password[index]
                # jsonl写入函数(使用w模式覆盖原记录)
                with open (self.user_encrypted_password_path,'w',encoding='utf-8') as f:
                    for item in self.user_encrypted_password:
                        f.write(json.dumps(item)+'\n')
                print(f'成功删除{given_weburl}网站的账号密码')

    # 密码生成函数,允许指定复杂度与长度 
    # 在函数内与用户交互，获得用户指定的复杂度与长度
    # 使用python自带的secrets库生成密码
    def password_generator(self):
        mode = 0
        length = 0
        while (mode != 1) and (mode != 2) and (mode != 3) and (mode != 4):
            mode = int(input("""
请选择您需要的密码复杂度
1.含有数字
2.含有数字和小写字母
3.含有数字、小写字母、大写字母
4.含有数字、小写字母、大写字母、特殊符号
"""))
        while True:
            length = input('请输入密码长度(不超过25的数字)')
            if length.isdigit() and 9 <= int(length) <= 25:
                length = int(length)
                break
        char_set = ''
        if mode >= 1:
            char_set += (string.digits)
        if mode >= 2:
            char_set += (string.ascii_lowercase)
        if mode >= 3:
            char_set += (string.ascii_uppercase)
        if mode >= 4:
            char_set += ('+/')
        if not char_set:
            char_set = string.digits
        print(f"密码生成成功:{''.join(secrets.choice(char_set) for _ in range(length))}")
    
    # Caesar加密
    def caesar_encrypt(self,text,shift):
        result =''
        for char in text:
            if char.isupper():
                result += chr((ord(char)-ord('A')+shift)%26+ord('A'))
            elif char.islower():
                result += chr((ord(char)-ord('a')+shift)%26+ord('a'))
            else:
                result += char
        return result
    # Caesar解密
    def caesar_decrypt(self,text,shift=3):
        return self.caesar_encrypt(text,-shift)
    
    # 异或加密解密
    # 使用用户主密码对待加密密码进行异或加密
    # 返回的是字节形式的加密后的密码
    def xor_encrypt_decrypt(self,text):
        # 若是字符串格式，则先变为字节序列；若是字节序列，则直接不变
        if isinstance(text,str):
            text_byte = text.encode('utf-8')
        elif isinstance(text,bytes):
            text_byte = text
        main_password_byte = self.user_main_password.encode('utf-8')
        # 将字节形式的主密码长度拓展至与待加密密码相同
        extended_main_password_byte = main_password_byte * (len(text_byte)//len(main_password_byte)+1)
        extended_main_password_byte = extended_main_password_byte[:len(text_byte)]
        # 进行异或加密
        result_byte =bytes([a ^ b for a, b in zip(text_byte, extended_main_password_byte)])
        return result_byte

    # 加密函数
    # 使用Caesar、异或加密、base64
    def total_encrypt(self,password,caesar_shift=3):
        # 凯撒加密(结果是字符串)
        caesar_encrypt_password = self.caesar_encrypt(password,caesar_shift)
        # 异或加密(结果是字节序列)
        xor_encrypt_password = self.xor_encrypt_decrypt(caesar_encrypt_password)
        # base64加密(结果是字节序列)
        base64_encrypt_byte = base64.b64encode(xor_encrypt_password)
        # 将字节序列变为字符串
        result = base64_encrypt_byte.decode('utf-8')
        return result
    # 解密函数
    def total_decrypt(self,encrypted_password,caesar_shift=3):
        # base64解密(需要先把字符串转化为字节序列,结果是字节序列)
        base64_decrypt = base64.b64decode(encrypted_password.encode('utf-8'))
        # 异或解密(结果是字节序列形式)
        xor_decrypt_byte = self.xor_encrypt_decrypt(base64_decrypt)
        # 将字节序列变为字符串
        xor_decrypt = xor_decrypt_byte.decode('utf-8')
        # 凯撒解密(结果是字符串)
        result = self.caesar_decrypt(xor_decrypt)
        return result


def show_menu_1():
    print("""
    欢迎使用密码管理系统！
          """)
if __name__ == '__main__':
    show_menu_1()
    pm = PasswordManager()
    while True:
        choice_1 = None
        while choice_1 not in ['0','1','2','3','4','5','6']: 
            choice_1 = input("""
请输入您需要进行的选项：
0.退出系统
1.登录用户账号
2.注册用户新账号
3.修改当前用户账号主密码(未登录状态下不可用)
4.删除当前用户账号(未登录状态下不可用)
5.退出当前用户账号
6.生成密码
""")
        if choice_1 == '0':
            print('感谢您的使用，再见!')
            break
        elif choice_1 == '2':
            pm.user_add()
        elif choice_1 =='3':
            if pm.user_log_stae ==False:
                print('请在登录状态下执行本操作')
            else:
                pm.user_change_main_password()
                print('已成功修改主密码')
        elif choice_1 =='4':
            if pm.user_log_stae ==False:
                print('请在登录状态下执行本操作')
            else:
                pm.user_delete()
                print('已成功退出并删除当前账号')
                pm = PasswordManager()
        elif choice_1 == '5':
            pm = PasswordManager()
            print("已退出当前账号")
        elif choice_1 == '6':
            pm.password_generator()
        elif choice_1 == '1':
            if pm.user_log_stae == True:
                print('当前已经登录')
            else:
                try_num_1 =0
                while pm.user_log_stae is False and try_num_1 <3:
                    pm.log_in()
                    try_num_1 += 1
                if try_num_1 == 3:
                    continue
                while True:
                    choice_2 = None
                    while choice_2 not in ['0','1','2','3','4','5']:
                        choice_2 = input("""
0.返回上一级目录
1.查看已保存密码的网站
2.查看网站密码
3.修改网站密码
4.删除网站密码
5.新增网站密码
""")
                    # 返回上一级目录
                    if choice_2 == '0':
                        break #结束上10行处开始的循环
                    # 查看已保存密码的网站
                    if choice_2 == '1':
                        pm.show_weburl()
                    # 查看网站密码
                    if choice_2 == '2':
                        index = 0
                        try_num_2 = 0
                        while (int(index) not in range(1,len(pm.user_encrypted_password)+1) and try_num_2 <3):
                            index = input('请输入想要查看的网站的序号')
                            try_num_2 +=1
                        pm.show_account_and_password(int(index))
                    # 修改网站密码
                    if choice_2 == '3':
                        pm.password_change_password()
                    # 删除网站密码
                    if choice_2 =='4':
                        pm.password_delete()
                    # 新增网站密码
                    if choice_2 =='5':
                        pm.password_add()