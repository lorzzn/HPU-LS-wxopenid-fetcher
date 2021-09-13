# -*- coding: utf-8 -*-

from scapy.all import *
import sys, re
import tkinter
import threading

from tkinter import ttk, messagebox

reload(sys)
sys.setdefaultencoding('utf-8')

reg = "remote/static/authIndex.*openid=((?=.*\d)(?=.*[a-z])(?=.*[A-Z])[\da-zA-Z-_]*)"

# GUI

root = tkinter.Tk()

class Menubar(ttk.Frame):
    """Builds a menu bar for the top of the main window"""
    def __init__(self, parent, *args, **kwargs):
        ''' Constructor'''
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        self.root = parent
        self.init_menubar()

    def on_exit(self):
        '''Exits program'''
        quit()

    def display_help(self):
        '''Displays help document'''
        pass

    def display_about(self):
        '''Displays info about program'''
        pass

    def init_menubar(self):
        self.menubar = tkinter.Menu(self.root)
        self.menu_file = tkinter.Menu(self.menubar) # Creates a "File" menu
        self.menu_file.add_command(label='退出', command=self.on_exit) # Adds an option to the menu
        self.menubar.add_cascade(menu=self.menu_file, label='选项') # Adds File menu to the bar. Can also be used to create submenus.

        # self.menu_help = tkinter.Menu(self.menubar) #Creates a "Help" menu
        # self.menu_help.add_command(label='帮助', command=self.display_help)
        # self.menu_help.add_command(label='关于', command=self.display_about)
        # self.menubar.add_cascade(menu=self.menu_help, label='帮助')

        self.root.config(menu=self.menubar)

class Window(ttk.Frame):
    """Abstract base class for a popup window"""
    # __metaclass__ = abc.ABCMeta
    def __init__(self, parent):
        ''' Constructor '''
        ttk.Frame.__init__(self, parent)
        self.parent = parent
        self.parent.resizable(width=False, height=False) # Disallows window resizing
        self.validate_notempty = (self.register(self.notEmpty), '%P') # Creates Tcl wrapper for python function. %P = new contents of field after the edit.
        self.init_gui()

    # @abc.abstractmethod # Must be overwriten by subclasses
    def init_gui(self):
        '''Initiates GUI of any popup window'''
        pass

    # @abc.abstractmethod
    def do_something(self):
        '''Does something that all popup windows need to do'''
        pass

    def notEmpty(self, P):
        '''Validates Entry fields to ensure they aren't empty'''
        if P.strip():
            valid = True
        else:
            print("Error: Field must not be empty.") # Prints to console
            valid = False
        return valid

    def close_win(self):
        '''Closes window'''
        self.parent.destroy()

class LisWindow(Window):
    """ New popup window """

    def __init__(self, parent):
        Window.__init__(self, parent)
        self.iid = None
        self.capture_res = []
        self.capture_res_index = 1

    def capture(self, x):
        global reg
        r_ip = str(x.payload.dst)
        r_body = str(x.lastlayer().original)
        pat = re.findall(reg, r_body)
        if pat:
            # print(r_body)
            print(pat[0])
            pat[0] = pat[0].decode("gbk","ignore")
            self.capture_res.append({
                'index': self.capture_res_index,
                'content': pat[0]
            })
            self.tree.insert("", self.capture_res_index, text=pat[0], values=(self.capture_res_index, pat[0]))  # #给第0行添加数据，索引值可重复
            self.capture_res_index += 1
            # print self.capture_res

    def start_capture(self):
        print 'capture start'
        try:
            sniff(filter="tcp", prn=lambda x: self.capture(x))
        except Exception as e:
            print e
            messagebox.showinfo('提示', '启动失败，请检查Winpcap是否已安装')

    def later_back_st(self):
        time.sleep(1.5)
        self.status_bar['text'] = '右键选择复制'

    def new_copy_act(self):
        copyStr = self.tree.item(self.iid)['text']
        root.clipboard_clear()
        root.clipboard_append(copyStr)
        self.status_bar['text'] = '复制成功'
        threading.Thread(target=self.later_back_st).start()

    def insert_data(self):

        def popup(event):
            """action in event of button 3 on tree view"""
            # select row under mouse
            self.iid = self.tree.identify_row(event.y)
            menu = tkinter.Menu(self.parent, tearoff=0)
            def onCopy():
                print 'copy: '+self.iid
                print self.tree.item(self.iid)
                # threading.Thread(target=self.new_copy_act, name='copy_thread').start()
                self.new_copy_act()

                # print copyStr
            def onDelete():
                print 'delete: '+self.iid
                self.tree.delete(self.iid)
            menu.add_command(label="复制", command=onCopy)
            menu.add_command(label="删除", command=onDelete)
            if self.iid:
                # mouse pointer over item
                self.tree.selection_set(self.iid)
                menu.post(event.x_root, event.y_root)
            else:
                pass

        self.tree = ttk.Treeview(self.parent, show='headings', height=500)  # #创建表格对象
        self.tree["columns"] = ("序号","内容")  # #定义列
        self.tree.column("序号", width=60)  # #设置列
        self.tree.column("内容", width=519)
        self.tree.heading("序号", text="序号")  # #设置显示的表头名
        self.tree.heading("内容", text="内容")
        self.tree.bind("<Button-3>", popup)

        # for i in range(0, 100):
        #     self.tree.insert("", i, text="", values=(i, "18"))  # #给第0行添加数据，索引值可重复
        # self.start_capture()
        capture_thread = threading.Thread(target=self.start_capture, name='capture_thread')
        capture_thread.setDaemon(True)
        capture_thread.start()

        self.VScroll1 = tkinter.Scrollbar(self.parent, orient='vertical', command=self.tree.yview)
        self.VScroll1.place(relx=0.97, rely=0.0, relwidth=0.03, relheight=1)
        # 给treeview添加配置
        self.tree.configure(yscrollcommand=self.VScroll1.set)
        self.tree.pack(side='left')

    def init_gui(self):
        self.parent.title("正在监听")
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(3, weight=1)
        sw = self.parent.winfo_screenwidth()
        # 得到屏幕宽度
        sh = self.parent.winfo_screenheight()
        # 得到屏幕高度
        ww = 600
        wh = 500
        # 窗口宽高为100
        x = (sw - ww) / 2
        y = (sh - wh) / 2
        self.parent.geometry("%dx%d+%d+%d" % (ww, wh, x+300, y))
        self.status_bar = ttk.Label(self.parent, text="鼠标右键选择复制", relief='sunken', anchor='w')
        self.status_bar.pack(side='bottom', fill='x')
        self.insert_data()


class SomethingWindow(Window):
    """ New popup window """

    # def __init__(self, GUI):
    #     super(SomethingWindow, self).__init__(GUI)

    def init_gui(self):
        self.parent.title("修改正则")
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(3, weight=1)

        sw = self.parent.winfo_screenwidth()
        # 得到屏幕宽度
        sh = self.parent.winfo_screenheight()
        # 得到屏幕高度
        ww = 400
        wh = 120
        # 窗口宽高为100
        x = (sw - ww) / 2
        y = (sh - wh) / 2
        self.parent.geometry("%dx%d+%d+%d" % (ww, wh, x, y))
        self.parent.attributes('-topmost', True)
        # Create Widgets

        self.label_title = ttk.Label(self.parent, text="请输入正则表达式")
        self.contentframe = ttk.Frame(self.parent, relief="sunken")

        self.label_test = ttk.Label(self.contentframe, text='正则表达式')
        self.input_test = ttk.Entry(self.contentframe, width=30, validate='focusout', validatecommand=(self.validate_notempty))

        self.btn_do = ttk.Button(self.parent, text='确定', command=self.do_something)
        self.btn_cancel = ttk.Button(self.parent, text='取消', command=self.close_win)

        # Layout
        self.label_title.grid(row=0, column=0, columnspan=2, sticky='nsew')
        self.contentframe.grid(row=1, column=0, columnspan=2, sticky='nsew')

        self.label_test.grid(row=0, column=0)
        self.input_test.grid(row=0, column=1, sticky='w')

        self.btn_do.grid(row=2, column=0, sticky='e')
        self.btn_cancel.grid(row=2, column=1, sticky='e')

        # Padding
        for child in self.parent.winfo_children():
            child.grid_configure(padx=10, pady=5)
        for child in self.contentframe.winfo_children():
            child.grid_configure(padx=5, pady=2)

    def do_something(self):
        '''Does something'''
        text = self.input_test.get().strip()
        if text:
            # Do things with text
            self.close_win()
            global reg
            reg = text
            GUI(root).edit_reg_text(reg)

        else:
            print("Error: But for real though, field must not be empty.")
            self.parent.attributes('-topmost', False)
            messagebox.showinfo('提示','输入不能为空')
            self.parent.attributes('-topmost', True)


class GUI(ttk.Frame):
    """Main GUI class"""
    def __init__(self, parent, *args, **kwargs):
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        self.root = parent
        self.init_gui()

    def edit_reg_text(self, newreg):
        self.label_title_reg = newreg

    def edit_reg(self):
        # res = simpledialog.SimpleDialog(self,)
        self.new_win = tkinter.Toplevel(self.root) # Set parent
        SomethingWindow(self.new_win)

    def start_lis(self):
        self.new_win = tkinter.Toplevel(self.root) # Set parent
        LisWindow(self.new_win)

    def init_gui(self):
        self.root.title('HPU图书馆系统openid获取工具 v2')
        # self.update()
        # self.update_idletasks()

        # self.columnconfigure(0, weight=1)
        # self.rowconfigure(3, weight=1)
        # root.maxsize(450, 200)
        # root.minsize(450, 200)
        root.resizable(False, False)
        sw = self.root.winfo_screenwidth()
        # 得到屏幕宽度
        sh = self.root.winfo_screenheight()
        # 得到屏幕高度
        ww = 450
        wh = 200
        # 窗口宽高为100
        x = (sw - ww) / 2
        y = (sh - wh) / 2
        self.root.geometry("%dx%d+%d+%d" % (ww, wh, x, y))
        self.grid(column=0, row=0, sticky='nsew')
        self.grid_columnconfigure(0, weight=1) # Allows column to stretch upon resizing
        self.grid_rowconfigure(0, weight=1) # Same with row
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.option_add('*tearOff', 'FALSE') # Disables ability to tear menu bar into own window

        # Menu Bar
        self.menubar = Menubar(self.root)

        # 界面对象
        # bs_S = ttk.Style()
        # bs_S.configure('my.TButton', font=('微软雅黑', 15))
        self.btn_start = ttk.Button(self, text='开始', command=self.start_lis)
        # self.img = tkinter.Canvas(self).create_image(100,100,image = tkinter.PhotoImage(file='./statics/icon.gif'))

        # self.img = tkinter.Label(self, image=)
        # Create Widgets
        self.label_title = ttk.Label(self, text="当前正则", font=("微软雅黑", 0, "bold"))
        global reg
        self.label_title_reg = ttk.Label(self, text=reg, wraplength  = 420, foreground='red')
        self.btn_er = ttk.Button(self, text='修改正则', command=self.edit_reg)

        # 布局
        self.btn_start.grid(row=0, column=0,sticky='ew')
        # self.img.grid(row=0, column=1, rowspan=2, sticky='e')
        self.label_title.grid(row=1, column=0, sticky='we')
        # self.label_title.pack(anchor='center')
        self.label_title_reg.grid(row=2, column=0, sticky='ew')
        self.btn_er.grid(row=3, column=0, sticky='ew')


        # Padding
        for child in self.winfo_children():
            child.grid_configure(padx=10, pady=5)


if __name__ == '__main__':
    GUI(root)
    root.mainloop()
    # start()
    # main_window()