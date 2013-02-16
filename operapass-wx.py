#!/usr/env python

from __future__ import print_function
import sys
from operapass import opwand
import os
import wx
import wx.gizmos as gizmos

class MyFrame(wx.Frame):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title=title, size=(550, 500))
        
        self.CreateStatusBar() # A Statusbar in the bottom of the window

        # Setting up the menu
        filemenu = wx.Menu()
        # wx.ID_ABOUT and wx.ID_EXIT are standard IDs provided by wxWidgets.
        menuitem_open = filemenu.Append(wx.ID_ANY, '&Open', 'Open(wand.dat) ...')
        menuitem_save = filemenu.Append(wx.ID_ANY, '&Export txt', 'Export to txt file...')
        menuitem_csv = filemenu.Append(wx.ID_ANY, '&Export csv', 'Export to csv file that use by lastpass')
        filemenu.AppendSeparator()
        menuitem_about = filemenu.Append(wx.ID_ABOUT, '&About', 'Information about this program')
        menuitem_exit = filemenu.Append(wx.ID_EXIT, 'E&xit', 'Terminate the program')
        # event
        self.Bind(wx.EVT_MENU, self.OnOpen, menuitem_open)
        self.Bind(wx.EVT_MENU, self.OnSave, menuitem_save)
        self.Bind(wx.EVT_MENU, self.OnSave_csv, menuitem_csv)
        self.Bind(wx.EVT_MENU, self.OnAbout, menuitem_about)
        self.Bind(wx.EVT_MENU, self.OnExit, menuitem_exit)
        # Creating the menubar
        menubar = wx.MenuBar()
        menubar.Append(filemenu, '&File') # Adding the "filemenu" to the MenuBar
        self.SetMenuBar(menubar) # Adding the MenuBar to the Frame content.
        
        
        self.searchCtrl1 = wx.SearchCtrl(self, -1, style=wx.TE_PROCESS_ENTER)
#        self.(wx.EVT_TEXT, self.RecreateTree)
        self.Bind(wx.EVT_TEXT, self.OnSearch)
        self.__init__treectl()
        
        self.sessionSizer = wx.BoxSizer(wx.VERTICAL)
        self.sessionSizer.AddWindow(self.searchCtrl1, 0,0, border=0)
        self.sessionSizer.AddWindow(self.tree, 1, wx.EXPAND, border=0)
        self.SetSizer(self.sessionSizer)
        #self.sessionSizer.Fit(self)
        self.filename = ''
        self.dirname = ''

    def __init__treectl(self):
        # init treectl
        self.tree = gizmos.TreeListCtrl(self, -1, style =
                                        wx.TR_DEFAULT_STYLE
                                        #| wx.TR_HAS_BUTTONS
                                        #| wx.TR_TWIST_BUTTONS
                                        #| wx.TR_ROW_LINES
                                        #| wx.TR_COLUMN_LINES
                                        #| wx.TR_NO_LINES
                                        | wx.TR_FULL_ROW_HIGHLIGHT
                                        | wx.TR_HIDE_ROOT
                                   )

        # create some columns
        self.tree.AddColumn("url")
        self.tree.AddColumn("username")
        self.tree.AddColumn("passwords")
        self.tree.SetMainColumn(0) # the one with the tree in it...
        self.tree.SetColumnWidth(0, 300)
        self.root = self.tree.AddRoot("wand data")
        self.tree.Expand(self.root)
        
    def OnShow(self, text, title):
        dlg = wx.MessageDialog(self, text, title, wx.OK)
        dlg.ShowModal()
        dlg.Destroy()

    def OnAbout(self, event):
        self.OnShow('A wand.dat reader', 'About Sample reader')

    def OnExit(self, e):
        self.Close(True)

    def OnOpen(self, e):
        """ Open the wand.dat file """
        Strfilter=""
        dlg = wx.FileDialog(self, 'Choose file', self.dirname,
                            '', 'wand.dat', wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.pwfile = dlg.GetPaths()[0]
            self.passwords = opwand.getData(self.pwfile)
            self.passwords = opwand.DecryptPwTextDatas(self.passwords)
            #print(self.passwords)
            self.OnLoad(self.passwords)
        dlg.Destroy()

    def OnSave(self, e):
        """ file to save """
        try:
            #self.OnShow('no file opened, save to...', 'notify')
            dlg = wx.FileDialog(self, 'save to file', self.dirname,
                            '', '*.txt', wx.SAVE)
            if dlg.ShowModal() == wx.ID_OK:
                self.pwfile = dlg.GetPaths()[0]
                fw = open(self.pwfile, 'w')
                flines = opwand.PrintTextData(self.passwords)
                fw.writelines(flines)
                fw.close()
                print('save OK!')
            dlg.Destroy()
        except e:
            print('save IOexcept')
    def OnLoad(self,pwdatas):
        self.pwdatas = []
        for pwdata in pwdatas:
            txt = "%s" % pwdata.onurl
            child = self.tree.AppendItem(self.root, txt)
            f1 = opwand.getFieldType(pwdata.fields,1)
            f2 = opwand.getFieldType(pwdata.fields,2)
            self.tree.SetItemText(child, f1, 1)
            self.tree.SetItemText(child, f2, 2)
            self.pwdatas.append([txt, f1, f2])
        self.tree.Expand(self.root)
        self.search_result = self.pwdatas

    def Refresh(self):
        self.tree.CollapseAll()
        self.Expand(self.root)
        
    def RecreateTree(self, pwdatas):
        #self.tree.Freeze()
        self.tree.DeleteAllItems()
        #self.__init__treectl()
        self.root = self.tree.AddRoot("wand data")
        for pwdata in pwdatas:
            child = self.tree.AppendItem(self.root, pwdata[0])
            self.tree.SetItemText(child, pwdata[1], 1)
            self.tree.SetItemText(child, pwdata[2], 2)

    def OnSearch(self, evt=None):
        value = self.searchCtrl1.GetValue()
        if not value:
            self.RecreateTree(self.pwdatas)
            return
        
        self.search_result = []
        for pwdata in self.pwdatas:
            if value in repr(pwdata):
                self.search_result.append(pwdata)
        self.RecreateTree(self.search_result)

    def OnSave_csv(self, e):
        """ file to save """
        try:
            #self.OnShow('no file opened, save to...', 'notify')
            dlg = wx.FileDialog(self, 'save to file', self.dirname,
                            '', '*.csv', wx.SAVE)
            if dlg.ShowModal() == wx.ID_OK:
                self.pwfile = dlg.GetPaths()[0]
                fw = open(self.pwfile, 'w')
                flines = []
                flines.append("name,username,password,url\n")
                for line in self.search_result:
                    if '//' not in line[0]:
                        continue
                    name = line[0].split("//")[1].split('/')[0]
                    username = line[1]
                    password = line[2]
                    url = line[0]
                    flines.append(','.join([name,username,password,url])+'\n')
                fw.writelines(flines)
                fw.close()
                print('save OK!')
            dlg.Destroy()
        except e:
            print('save IOexcept')

if __name__ == '__main__':
    app = wx.App(False)
    frame = MyFrame(None, 'Sample reader')
    frame.Show()
    app.MainLoop()
