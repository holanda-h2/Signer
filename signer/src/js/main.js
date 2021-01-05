"use strict";

const { app, BrowserWindow, Menu, ipcMain } = require('electron')
const { buildMenuTemplate } = require('./menutemplate')
const spawn = require('child_process').spawn;

const fs = require('fs');
const cipher = require('./cipher');

global.sharedObject = {
    nome_do_arquivo: null
}

let win, aboutWin, signWin, configWin, checkWin, passWin, logWin

function createWindow() {
    win = new BrowserWindow({
        width: 800,
        height: 600,
        minWidth: 300,
        minHeight: 300,
        icon: './src/assets/images/signer.png',
        webPreferences: {
            plugins: true,
            nodeIntegration: true
        },
        frame: false
    })

    win.loadFile('./src/index.html')
        //   win.webContents.openDevTools();

    win.on('closed', () => {
        win = null;
        aboutWin = null;
        signWin = null;
        configWin = null;
        passWin = null;
        logWin = null;
    })

    const menu = Menu.buildFromTemplate(buildMenuTemplate(win))

    menu.getMenuItemById('about').click = () => {
        if (!aboutWin) {
            aboutWin = new BrowserWindow({
                width: 400,
                height: 150,
                resizable: false,
                frame: false,
                parent: win,
                modal: true,
                webPreferences: {
                    nodeIntegration: true
                },
            })

            aboutWin.loadFile('./src/about.html')
                //  aboutWin.loadFile('algo2.html')

            aboutWin.on('closed', () => {
                aboutWin = null
            })
        }
    }

    menu.getMenuItemById('sign').click = () => {
        if (!signWin) {
            signWin = new BrowserWindow({
                width: 520,
                height: 400,
                resizable: true,
                frame: false,
                parent: win,
                modal: true,
                webPreferences: {
                    nodeIntegration: true
                },
            })

            signWin.loadFile('./src/signature.html')

            signWin.on('closed', () => {
                signWin = null
            })
        }
    }

    menu.getMenuItemById('configuration').click = () => {
        if (!configWin) {
            configWin = new BrowserWindow({
                width: 420,
                height: 330,
                resizable: true,
                frame: false,
                parent: win,
                modal: true,
                webPreferences: {
                    nodeIntegration: true
                },
            })

            configWin.loadFile('./src/configuration.html')

            configWin.on('closed', () => {
                configWin = null
            })

            configWin.webContents.on('did-finish-load', () => {
                var content = fs.readFileSync("./configuration.json");
                var obj = JSON.parse(content);
                let passwordDecrypt = cipher.AESCripto.decrypt(obj.password);
                obj.password = passwordDecrypt;
                configWin.webContents.send('load-config', obj);
            })
        }
    }

    menu.getMenuItemById('log').click = () => {
        if (!logWin) {
            logWin = new BrowserWindow({
                width: 680,
                height: 365,
                resizable: true,
                frame: false,
                parent: win,
                modal: true,
                webPreferences: {
                    nodeIntegration: true
                }
            })

            logWin.loadFile('./src/log.html')

            logWin.on('closed', () => {
                logWin = null
            })

            logWin.webContents.on('did-finish-load', () => {
                var content = fs.readFileSync("./signer.log", 'utf8');
                // var content = fs.readFileSync("./src/img/image1.p7s", 'hex');
                logWin.webContents.send('load-log', content);
            })
        }
    }

    menu.getMenuItemById('password').click = () => {
        if (!passWin) {
            passWin = new BrowserWindow({
                width: 340,
                height: 170,
                resizable: true,
                frame: false,
                parent: win,
                modal: true,
                webPreferences: {
                    nodeIntegration: true
                }
            })

            passWin.loadFile('./src/password.html')

            passWin.on('closed', () => {
                passWin = null
            })

        }
    }

    menu.getMenuItemById('check').click = () => {
        checkWin = new BrowserWindow({
            width: 420,
            height: 340,
            resizable: true,
            //  useContentSize: true,
            frame: false,
            parent: win,
            modal: true,
            //    show: false,
            //  opacity: 0.5,
            webPreferences: {
                nodeIntegration: true
            },
        })

        checkWin.loadFile('./src/check.html')

        checkWin.webContents.on('did-finish-load', () => {
            execCMDCC(global.sharedObject.nome_do_arquivo);
        })

        checkWin.on('closed', () => {
            checkWin = null
        })
    }

    Menu.setApplicationMenu(menu)

    ipcMain.on('toggle-menu-items', (event, flag) => {
        menu.getMenuItemById('file-print').enabled = flag
        menu.getMenuItemById('file-properties').enabled = flag
        menu.getMenuItemById('file-close').enabled = flag
        menu.getMenuItemById('view-fullscreen').enabled = flag
        menu.getMenuItemById('check').enabled = flag
        menu.getMenuItemById('password').enabled = flag
    })

    const execCMD = function(path) {
        let pinCryto = cipher.AESCripto.encrypt(path.pin);
        let action = 'C';
        if (path.type == 'PAdES') {
            action = 'S';
        } else if (path.type == 'XAdES') {
            action = 'D';
        } else if (path.type == 'XSig') {
            action = 'X';
        } else {
            action = 'E';
        }
        let passCryto = cipher.AESCripto.encrypt(path.file_password);

        const child = spawn('java', ['-jar', './/signer-0.0.1.jar', action, path.device, path.path, pinCryto, path.file_name, passCryto]);

        child.on('exit', code => {
            signWin.webContents.send('sign-file-msg', 'Signed!');
            let extension = '';
            var files = path.path.split(";");
            for (var i = 0; i < files.length; i++) {
                var arqs = files[i].substr(0, files[i].length - 4);

                if (path.type == 'PAdES') {
                    extension = '-signed.pdf';
                } else if (path.type == 'XAdES') {
                    extension = '-xades.xml';
                } else if (path.type == 'XSig') {
                    extension = '-signed.xml';
                } else {
                    extension = '.' + files[i].substring(files[i].length - 3, files[i].length).toLowerCase();;
                }
                win.webContents.send('file-open', arqs + extension);
            }
        });
    }

    const execCMDCC = function(path) {

        let extension = path.substring(path.length - 3, path.length).toLowerCase();
        let action = '';
        if (extension == "pdf") {
            action = "C";
        } else if (extension == "xml") {
            action = "V";
        } else {
            action = "F";
        }

        const childA = spawn('java', ['-jar', './/signer-0.0.1.jar', action, path]);

        childA.stdout.on('data', (data) => {
            var objX = JSON.parse(data);
            checkWin.webContents.send('sign-check', objX);
        });
    }

    ipcMain.on('sign-file', (event, path) => {
        signWin.webContents.send('sign-file-msg', 'signing...');
        execCMD(path);
    });

    ipcMain.on('config-save', (event, obj) => {
        let passwordCrypto = cipher.AESCripto.encrypt(obj.password)
        obj.password = passwordCrypto;
        var objJSON = JSON.stringify(obj);
        fs.writeFileSync('./configuration.json', objJSON);
    });

    ipcMain.on('config-detect', (event) => {
        const childAux = spawn('java', ['-jar', './/signer-0.0.1.jar', 'T']);

        childAux.stdout.on('data', (data) => {
            configWin.webContents.send('config-detect-driver', data);
        });
    });

    ipcMain.on('add-password', (event, oldPassword, newPassword) => {
        var oldPasswordAux = oldPassword;
        if (oldPassword.length > 0) {
            oldPasswordAux = cipher.AESCripto.encrypt(oldPassword);
        }
        var newPasswordAux = newPassword;
        if (newPassword.length > 0) {
            newPasswordAux = cipher.AESCripto.encrypt(newPassword);
        }

        const childAux = spawn('java', ['-jar', './/signer-0.0.1.jar', 'P',
            global.sharedObject.nome_do_arquivo,
            oldPasswordAux,
            newPasswordAux
        ]);

    });

}

app.on('ready', createWindow)

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit()
    }
})

app.on('activate', () => {
    if (win === null) {
        createWindow()
    }
})