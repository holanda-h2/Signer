"use strict";

const { app, dialog } = require('electron')

exports.buildMenuTemplate = function(win) {
    return [{
            label: 'File',
            submenu: [{
                    label: 'Open...',
                    id: 'file-open',
                    accelerator: 'CmdOrCtrl+O',
                    click() {
                        dialog.showOpenDialog(win, {
                                properties: ['openFile'],
                                filters: [
                                    { name: 'PDF Files', extensions: ['pdf'] },
                                    { name: 'XML Files', extensions: ['xml'] },
                                    { name: 'Image Files', extensions: ['jpg', 'png', 'bmp', 'svg', 'gif'] }
                                ]
                            },
                            (filename) => {
                                if (filename) {
                                    win.webContents.send('file-open', filename.toString())
                                }
                            })
                    }
                },
                {
                    label: 'Print...',
                    id: 'file-print',
                    accelerator: 'CmdOrCtrl+P',
                    enabled: false,
                    click() {
                        win.webContents.send('file-print')
                    }
                },
                {
                    type: 'separator'
                },
                {
                    label: 'Properties...',
                    id: 'file-properties',
                    enabled: false,
                    click() {
                        win.webContents.send('file-properties')
                    }
                },
                {
                    type: 'separator'
                },
                {
                    label: 'Close',
                    id: 'file-close',
                    enabled: false,
                    click() {
                        win.webContents.send('file-close')
                    }
                },
                {
                    label: 'Exit',
                    click() {
                        app.quit()
                    }
                }
            ]
        },
        {
            label: 'View',
            submenu: [{
                label: 'Toggle Full Screen',
                id: 'view-fullscreen',
                enabled: false,
                accelerator: 'F11',
                click() {
                    win.webContents.send('view-fullscreen')
                }
            }]
        },
        {
            label: 'Signature',
            submenu: [{
                    label: 'Sign...',
                    id: 'sign',
                    enabled: true
                },
                {
                    label: 'Check...',
                    id: 'check',
                    enabled: false
                },
                {
                    label: 'Configuration...',
                    id: 'configuration'
                },
                {
                    label: 'File Log...',
                    id: 'log'
                },
                {
                    type: 'separator'
                },
                {
                    label: 'Password...',
                    id: 'password',
                    enabled: false
                }
            ]
        },
        {
            label: 'Help',
            submenu: [{
                label: 'About',
                id: 'about'
            }]
        }

    ]
}