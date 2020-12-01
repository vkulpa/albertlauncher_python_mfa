# -*- coding: utf-8 -*-

"""Generation Time based One Time Password"""

import os

import keyring
import oathtool
from albert import *

__doc__ = "Generates Time base One Time Passwords"
__title__ = "mfa"
__version__ = "0.4.1"
__triggers__ = ["mfa "]
__authors__ = ["Volodymyr Kulpa"]
__py_deps__ = ["keyring", "oathtool"]

__trigger__ = "mfa "
add_icon = os.path.dirname(__file__) + '/icon-add.svg'
remove_icon = os.path.dirname(__file__) + '/icon-remove.svg'
icon = os.path.dirname(__file__) + '/icon-mfa.svg'


class Mfa:
    def __init__(self):
        self.users = set(
            (keyring.get_password(__title__, 'accounts') or '').split())

    def add(self, user, secret):
        self.users.add(user)
        self.__update_accounts()
        keyring.set_password(__title__, user, secret)

    def remove(self, user):
        self.users.remove(user)
        self.__update_accounts()
        keyring.delete_password(__title__, user)

    def list_users(self):
        return self.users

    def generate(self, user):
        return self.__generate(keyring.get_password(__title__, user))

    def try_generate(self, secret):
        return self.__generate(secret)

    def __update_accounts(self):
        if len(self.users) > 0:
            keyring.set_password(__title__, 'accounts', ' '.join(self.users))
        else:
            keyring.delete_password(__title__, 'accounts')

    def __generate(self, secret):
        try:
            return oathtool.generate_otp(secret)
        except Exception:
            warning('Could not generate OTP for secret %s' % secret)

        return ''


def initialize():
    global mfa
    mfa = Mfa()


def handleQuery(query):
    if not query.isTriggered:
        return

    results = []

    parts = query.string.split()

    for account in mfa.list_users():
        if len(query.string.strip()) > 0 and not account.startswith(
                query.string.strip()):
            continue

        otp = mfa.generate(account)
        if otp == '':
            continue

        results.append(Item(icon=icon,
                            text='%s %s' % (account, otp),
                            completion='%s %s' % (
                                __trigger__.strip(), account),
                            actions=[
                                ClipAction(text=account, clipboardText=otp)
                            ]))

    results += addActions(parts)

    return results


def addActions(parts):
    results = []

    addItem = Item(icon=add_icon,
                   text='Add secret',
                   completion='%s add ' % __trigger__.strip(),
                   subtext='%s add secret-name secret-totp' % __trigger__.strip())
    removeItem = Item(icon=remove_icon,
                      text='Remove secret',
                      completion='%s remove ' % __trigger__.strip(),
                      subtext='%s remove secret-name' % __trigger__.strip())

    if len(parts) == 3 and parts[0] == 'add':
        addItem.addAction(FuncAction(text='Adds secret',
                                     callable=lambda user=parts[1],
                                                     secret=''.join(
                                                         parts[2:]): mfa.add(
                                         user, secret)))
    elif len(parts) == 2 and parts[0] == 'remove':
        results += removeSuggestion(parts[1])

        removeItem.addAction(
            FuncAction(text='Removes secret',
                       callable=lambda user=parts[1]: mfa.remove(user)))

    if len(parts) == 0 or parts[0] in ('a', 'ad', 'add'):
        results.append(addItem)

    if len(parts) == 0 or parts[0] in (
            'r', 're', 'rem', 'remo', 'remov', 'remove'):
        if len(parts) == 1:
            results += removeSuggestion('')

        results.append(removeItem)

    return results


def removeSuggestion(name):
    results = []
    for account in mfa.list_users():
        if len(name) > 0 and not account.startswith(name):
            continue

        results.append(Item(icon=remove_icon,
                            text='Remove %s' % account,
                            completion='%s remove %s' % (
                                __trigger__.strip(), account),
                            actions=[
                                FuncAction(text='Remove secret',
                                           callable=lambda
                                               user=name: mfa.remove(user)
                                           )
                            ]))
    return results
