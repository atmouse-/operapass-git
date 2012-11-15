#!/usr/env python

from __future__ import print_function
import sys
from operapass import opwand
import os
import wx
import  wx.gizmos   as  gizmos
class ContPanel(wx.Panel):
    def __init__(self, parent, pos):

        wx.Panel.__init__(self, parent, -1, pos, size=(550,380))
        self.Bind(wx.EVT_SIZE, self.OnSize)

        self.tree = gizmos.TreeListCtrl(self, -1, style =
                                        wx.TR_DEFAULT_STYLE
                                        #| wx.TR_HAS_BUTTONS
                                        #| wx.TR_TWIST_BUTTONS
                                        #| wx.TR_ROW_LINES
                                        #| wx.TR_COLUMN_LINES
                                        #| wx.TR_NO_LINES
                                        | wx.TR_FULL_ROW_HIGHLIGHT
                                   )

        isz = (16,16)
        il = wx.ImageList(isz[0], isz[1])
        fldridx     = il.Add(wx.ArtProvider_GetBitmap(wx.ART_FOLDER,      wx.ART_OTHER, isz))
        fldropenidx = il.Add(wx.ArtProvider_GetBitmap(wx.ART_FILE_OPEN,   wx.ART_OTHER, isz))
        fileidx     = il.Add(wx.ArtProvider_GetBitmap(wx.ART_NORMAL_FILE, wx.ART_OTHER, isz))

        self.tree.SetImageList(il)
        self.il = il

        # create some columns
        self.tree.AddColumn("url")
        self.tree.AddColumn("username")
        self.tree.AddColumn("passwords")
        self.tree.SetMainColumn(0) # the one with the tree in it...
        self.tree.SetColumnWidth(0, 300)


        self.root = self.tree.AddRoot("wand data")

        self.tree.Expand(self.root)

        self.tree.GetMainWindow().Bind(wx.EVT_RIGHT_UP, self.OnRightUp)
        self.tree.Bind(wx.EVT_TREE_ITEM_ACTIVATED, self.OnActivate)
        self.tree.SetSize(self.GetSize())
    def OnLoad(self,pwdatas):
        self.pwdatas = pwdatas
        for pwdata in self.pwdatas:
            txt = "%s" % pwdata.onurl
            child = self.tree.AppendItem(self.root, txt)
            self.tree.SetItemText(child, opwand.getFieldType(pwdata.fields,1), 1)
            self.tree.SetItemText(child, opwand.getFieldType(pwdata.fields,2), 2)
        self.tree.Expand(self.root)

    def Refresh(self):
        self.tree.CollapseAll()
        self.Expand(self.root)
        
    def RecreateTree(self, evt=None):
        self.tree.Freeze()
        self.tree.DeleteAllItems()
        self.__init__()
        for pwdata in self.pwdatas:
            txt = "%s" % self.pwdata.onurl
            child = self.tree.AppendItem(self.root, txt)
            self.tree.SetItemText(child, opwand.getFieldType(pwdata.fields,1), 1)
            self.tree.SetItemText(child, opwand.getFieldType(pwdata.fields,2), 2)

    def OnSearch(self, evt=None):
        value = self.filter.GetValue()
        if not value:
            self.RecreateTree()
            return

        wx.BeginBusyCursor()
        for pwdata in self.pwdatas:
            if value in pwdata.onurl:
                pass
        for category, items in _treeList:
            self.searchItems[category] = []
            for childItem in items:
                if SearchDemo(childItem, value):
                    self.searchItems[category].append(childItem)

        wx.EndBusyCursor()
        self.RecreateTree()
        
    def OnActivate(self, evt):
        print('OnActivate: %s' % self.tree.GetItemText(evt.GetItem(), 1))


    def OnRightUp(self, evt):
        pos = evt.GetPosition()
        item, flags, col = self.tree.HitTest(pos)
        if item:
            self.log.write('Flags: %s, Col:%s, Text: %s' %
                           (flags, col, self.tree.GetItemText(item, col)))

    def OnSize(self, evt):
        self.tree.SetSize(self.GetSize())
class SearchPanel(wx.Panel):
    def __init__(self, parent):
        [wxID_FRAME1, wxID_FRAME1BUTTON1, wxID_FRAME1BUTTON2, wxID_FRAME1PANEL1,
         wxID_FRAME1RADIOBUTTON1, wxID_FRAME1RADIOBUTTON2, wxID_FRAME1SEARCHCTRL1,
         wxID_FRAME1STATICBOX1, wxID_FRAME1TREELISTCTRL1,
        ] = [wx.NewId() for _init_ctrls in range(9)]
        wx.Panel.__init__(self, parent, -1, size=(648, 50))
        self.staticBox1 = wx.StaticBox(id=wxID_FRAME1STATICBOX1,
                        label='Search', name='staticBox1', parent=self,
                        pos=wx.Point(0,0), size=wx.Size(280, 48), style=0)
        self.radioButton1 = wx.RadioButton(id=wxID_FRAME1RADIOBUTTON1,
                        label='ByDomain', name='radioButton1', parent=self,
                        pos=wx.Point(36, 26), size=wx.Size(108, 18), style=0)

        self.radioButton2 = wx.RadioButton(id=wxID_FRAME1RADIOBUTTON2,
                        label='ByUserName', name='radioButton2', parent=self,
                        pos=wx.Point(152, 26), size=wx.Size(108, 18), style=0)
        self.searchCtrl1 = wx.SearchCtrl(id=wxID_FRAME1SEARCHCTRL1,
                        name='searchCtrl1', parent=self, pos=wx.Point(320, 16),
                        size=wx.Size(134, 26), style=0, value='searchCtrl1')
        #self.control = wx.TextCtrl(self, style=wx.TE_MULTILINE)

class MyFrame(wx.Frame):
    """ We simply derive a new class of Frame. """

    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title=title, size=(550, 483))
        self.panel = wx.Panel(self)
        self.panel1 = SearchPanel(self.panel)
        self.panel2 = ContPanel(self.panel, pos=(0,50))
        self.filename = ''
        self.dirname = ''
        self.CreateStatusBar() # A Statusbar in the bottom of the window

        # Setting up the menu
        filemenu = wx.Menu()

        # wx.ID_ABOUT and wx.ID_EXIT are standard IDs provided by wxWidgets.
        menuitem_open = filemenu.Append(wx.ID_ANY, '&Open', 'Open file...')
        menuitem_save = filemenu.Append(wx.ID_ANY, '&Export2txt', 'Export to file...')
        filemenu.AppendSeparator()
        menuitem_about = filemenu.Append(wx.ID_ABOUT, '&About', 'Information about this program')
        menuitem_exit = filemenu.Append(wx.ID_EXIT, 'E&xit', 'Terminate the program')

        # event
        self.Bind(wx.EVT_MENU, self.OnOpen, menuitem_open)
        self.Bind(wx.EVT_MENU, self.OnSave, menuitem_save)
        self.Bind(wx.EVT_MENU, self.OnAbout, menuitem_about)
        self.Bind(wx.EVT_MENU, self.OnExit, menuitem_exit)

        # Creating the menubar
        menubar = wx.MenuBar()
        menubar.Append(filemenu, '&File') # Adding the "filemenu" to the MenuBar
        self.SetMenuBar(menubar) # Adding the MenuBar to the Frame content.
        self.Show(True)

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
                            '', '*', wx.OPEN)
        if dlg.ShowModal() == wx.ID_OK:
            self.pwfile = dlg.GetPaths()[0]
            self.passwords = opwand.getData(self.pwfile)
            self.passwords = opwand.DecryptPwTextDatas(self.passwords)
            self.panel2.OnLoad(self.passwords)
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

if __name__ == '__main__':
    app = wx.App(False)
    frame = MyFrame(None, 'Sample reader')
    app.MainLoop()
