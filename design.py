# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'design.ui'
##
## Created by: Qt User Interface Compiler version 6.8.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QFrame, QLabel, QMainWindow,
    QPushButton, QSizePolicy, QStatusBar, QVBoxLayout,
    QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(793, 596)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.frame = QFrame(self.centralwidget)
        self.frame.setObjectName(u"frame")
        self.frame.setGeometry(QRect(-1, -1, 801, 591))
        self.frame.setAutoFillBackground(False)
        self.frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.frame.setFrameShadow(QFrame.Shadow.Raised)
        self.Image_to_Show = QLabel(self.frame)
        self.Image_to_Show.setObjectName(u"Image_to_Show")
        self.Image_to_Show.setGeometry(QRect(340, 0, 461, 581))
        self.Image_to_Show.setPixmap(QPixmap(u"encrypt-any-file.png"))
        self.Image_to_Show.setScaledContents(True)
        self.verticalLayoutWidget = QWidget(self.frame)
        self.verticalLayoutWidget.setObjectName(u"verticalLayoutWidget")
        self.verticalLayoutWidget.setGeometry(QRect(50, 130, 251, 261))
        self.verticalLayout = QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.btn_select_file = QPushButton(self.verticalLayoutWidget)
        self.btn_select_file.setObjectName(u"btn_select_file")

        self.verticalLayout.addWidget(self.btn_select_file)

        self.btn_decrypt_file = QPushButton(self.verticalLayoutWidget)
        self.btn_decrypt_file.setObjectName(u"btn_decrypt_file")

        self.verticalLayout.addWidget(self.btn_decrypt_file)

        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.Image_to_Show.setText("")
        self.btn_select_file.setText(QCoreApplication.translate("MainWindow", u"Encryte a file ", None))
        self.btn_decrypt_file.setText(QCoreApplication.translate("MainWindow", u" Decrypt a file ", None))
    # retranslateUi

