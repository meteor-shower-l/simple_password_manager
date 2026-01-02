# 迭代点：
# 1.read_jsonl的异常处理

# user_info结构:[{'username':用户名,'password':主密码,},...]
# user_encrypted_password_path结构:[{'weburl':网址,'username':用户名,'password':密码},...]

import os
import json
import getpass
import string
import secrets
from pathlib import Path
import base64
import hashlib

class PasswordManager:

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
    # 判断字符串是否是字典列表中某个元素的键，并返回其位置
    def get_index_key_in_dict_list(self,given_key,dict_list):
        result = None
        for i in range(0,len(dict_list)):
            if given_key in ((dict_list[i]).values()):
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
        self.user_encrypted_password_path =''
        self.user_encrypted_password = []
        self.user_main_password =''

    # 登录函数，用于完成用户登录，也可以切换账号
    # 在此函数中，完成用户主密码的赋值与加密密码本的读入
    # 注意添加哈希算法
    def log_in(self):
        given_username = input("请输入用户名")
        given_userpassword = getpass("请输入用户密码")
        index = self.get_index_key_in_dict_list(given_username)
        if index !=None:
            if  self.user_info[index]['username'] == given_userpassword: # 若匹配成功(明文)
                self.user_main_password = given_userpassword # 将用户输入的密码储存为密码(明文)
                self.user_encrypted_password_path = self.path(f'{given_username}_password.jsonl')
                self.user_encrypted_password = self.read_jsonl(self.user_encrypted_password_path) # 读取文件中的密码至内存
                print('登录成功')
            else:
                print('登录失败,用户名或密码有误')
        else: 
            print('登录失败,用户名或密码有误')

    # 有设计地不提供用户名列表
    # 从而进一步降低账号被盗的可能

    # 网址展示函数
    def show_weburl(self):
        print('目前已管理密码的网站网址如下:')
        for i in range(0,len(self.user_encrypted_password)):
            print(f'{i+1}.',end='')
            print(self.user_encrypted_password[i]('weburl'))
    
    # 账号密码打印函数
    def show_account_and_password(self,index):
        print(f'{self.user_encrypted_password[index]['weburl']}的账号密码如下:')
        print(f'账号:{self.user_encrypted_password[index]['username']}')
        print(f'密码:{self.user_encrypted_password[index]['password']}')

    # 新增用户函数
    # 使用getpass防止密码在屏幕可以见,使用while True循环确保两次密码相同
    # 更新内存中储存的用户列表
    def user_add(self):
        given_username = input('请输入用户名')
        # 先判断用户是否存在
        # 若存在，则提示并直接退出
        if self.get_index_key_in_dict_list(given_username,self.user_info) != None:
            print('用户已存在')
        # 若不存在，则提示用户输入密码
        else:
            while True:
                given_password_1 = getpass('请输入密码')
                given_password_2 = getpass('请再次输出密码以确认')
                if given_password_1 == given_password_2:
                    break
                else:
                    print('两次输入的密码不同，请重新输入')
            info_dict = {"username":given_username,"password":given_password_1}
            with open(self.USER_INFO_PATH,'a',encoding='utf-8') as f:
                f.write(json.dumps(info_dict)+'\n')
            self.user_info.append(info_dict)
            print(f'成功创建新用户')

    # 修改用户主密码函数
    # 更新内存中储存的用户列表
    # 通过重新写入更新user_info.jsonl，存在IO频繁问题,需要迭代完善
    def user_change_main_password(self):
        given_username = input('请输入要修改密码的用户名')
        index=self.get_index_key_in_dict_list(given_username,self.user_info)
        if index == None:
            print('用户不存在，无法修改密码')
        else:
            given_userpassword = getpass('请输入原密码')
            if given_userpassword != self.user_info[given_username]:
                print('原始密码错误，请确认原密码后再修改')
            else:
                while True:
                    given_password_1 = getpass('请输入密码')
                    given_password_2 = getpass('请再次输出密码以确认')
                    if given_password_1 == given_password_2:
                        break
                    else:
                        print('两次输入的密码不同，请重新输入')
                self.user_info[index]['password'] = given_password_1
                # jsonl写入
                print(f'成功修改用户{given_username}的密码')

    # 删除用户函数
    # 更新内存中储存的用户列表
    # 通过重新写入更新user_info.jsonl，存在IO频繁问题,需要迭代完善
    def user_delete(self):
        given_username = input('请输入要删除的用户')
        index=self.get_index_key_in_dict_list(given_username,self.user_info)
        if  index == None:
            print('用户不存在')
        else:
            given_userpassword = getpass('请输入原码')
            if given_userpassword != self.user_info[index]['username']:
                print('密码错误，请确认密码后再修改')
            else:
                del self.user_info[index]
                # jsonl写入
                print(f'成功删除用户{given_username}')

    # 新增账号密码函数
    # 使用getpass防止密码在屏幕可以见,使用while True循环确保两次密码相同
    # 更新内存中储存的用户密码列表
    # 直接更新user_password.jsonl文件
    
    def password_add(self):
        given_weburl = input('请输入需要添加的网址')
        index = self.get_index_key_in_dict_list(given_weburl,self.user_encrypted_password)
        if index != None:
            print(f'网站{given_weburl}账号密码已存在')
        else:
            given_username = input('请输入用户名')
            while True:
                given_password_1 = getpass('请输入密码')
                given_password_2 = getpass('请再次输入密码以确认')
                if given_password_1 == given_password_2:
                    break
            weburl_username_password ={'weburl':given_weburl,
                                    'username':given_username,
                                    'password':given_password_1}
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
        index = self.get_index_key_in_dict_list(given_weburl,self.user_encrypted_password)
        if index == None:
            print(f'不存在网址为{given_weburl}的账号密码')
        else:
            while True:
                given_password_1 = getpass('请输入密码')
                given_password_2 = getpass('请再次输出密码以确认')
                if given_password_1 == given_password_2:
                    break
                else:
                    print('两次输入的密码不同，请重新输入')
        self.user_encrypted_password[index]['password'] = given_password_2
        # jsonl写入函数
        print(f'已成功修改{given_weburl}网站的密码')

    # 删除网站密码函数
    # 使用getpass防止密码在屏幕可以见
    # 更新内存中储存的用户密码列表
    # 通过重新写入更新user_info.jsonl，存在IO频繁问题,需要迭代完善
    def password_delete(self):
        given_weburl = input('请输入要修改密码的网址')
        index = self.get_index_key_in_dict_list(given_weburl,self.user_encrypted_password)
        if index == None:
            print(f'不存在网址为{given_weburl}的账号密码')
        else:
            given_password = getpass('请输入您的主密码,以完成身份认证')
            if given_password != self.user_main_password:
                print('密码错误，请确认密码后再修改')
            else:
                del self.user_encrypted_password[index]
                # jsonl写入函数
                print(f'成功删除{given_password}网站的账号密码')

    # 密码生成函数,允许指定复杂度与长度 
    # 在函数内与用户交互，获得用户指定的复杂度与长度
    # 使用python自带的secrets库生成密码
    def password_genertor(self):
        mode = 0
        length = 0
        while (mode != 1) and (mode != 2) and (mode != 3) and (mode != 4):
            mode = input("""请选择您需要的密码复杂度
                        1.含有数字
                        2.含有数字和小写字母
                        3.含有数字、小写字母、大写字母
                        4.含有数字、小写字母、大写字母、特殊符号
                        """)
        while (length not in range(1,25) or length.isdigit() == False):
            length = input('请输入密码长度(不超过25的数字)')
        char_set = ''
        if mode >= 1:
            char_set.join(string.digits)
        if mode >= 2:
            char_set.join(string.ascii_lowercase)
        if mode >= 3:
            char_set.join(string.ascii_uppercase)
        if mode >= 4:
            char_set.join('+/')
        return ''.join(secrets.choice(char_set) for _ in range(length))
    
    # Caesar加密
    def caesar_encrypt(self,text,shift):
        result =''
        for char in text:
            if char.isupper():
                result += chr((ord(char)-ord('A')+shift)%26+ord('A'))
            if char.islower():
                result += chr((ord(char)-ord('a')+shift)%26+ord('a'))
            else:
                result += char
    # Caesar解密
    def caesar_decrypt(self,text,shift):
        return self.caesar_encrypt(text,-shift)

    # 加密函数
    # 使用base64、Caesar、异或
