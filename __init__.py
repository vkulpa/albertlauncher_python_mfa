# -*- coding: utf-8 -*-
#  Copyright (c) 2023 Volodymyr Kulpa

import os

import keyring
import oathtool
from albert import *

md_iid = "1.0"
md_version = "0.2"
md_id = "mfa"
md_name = "mfa"
md_description = "MFA plugins which helps use add/remove/copy/past your 2fa codes"
md_license = "BSD-3"
md_url = "https://github.com/vkulpa/albertlauncher_python_mfa"
md_lib_dependencies = ["oathtool", "keyring"]


class Mfa:
    def __init__(self):
        self.users = set(
            (keyring.get_password(md_name, 'accounts') or '').split())

    def add(self, user, secret):
        self.users.add(user)
        self.__update_accounts()
        keyring.set_password(md_name, user, secret)

    def remove(self, user):
        self.users.remove(user)
        self.__update_accounts()
        keyring.delete_password(md_name, user)

    def list_users(self):
        return self.users

    def generate(self, user):
        return self.__generate(keyring.get_password(md_name, user))

    def try_generate(self, secret):
        return self.__generate(secret)

    def __update_accounts(self):
        if len(self.users) > 0:
            keyring.set_password(md_name, 'accounts', ' '.join(self.users))
        else:
            keyring.delete_password(md_name, 'accounts')

    def __generate(self, secret):
        try:
            return oathtool.generate_otp(secret)
        except Exception:
            warning('Could not generate OTP for secret %s' % secret)
            return -1


class Plugin(TriggerQueryHandler):
    icon_add = [os.path.dirname(__file__) + '/icon-add.svg']
    icon_remove = [os.path.dirname(__file__) + '/icon-remove.svg']
    icon_mfa = [os.path.dirname(__file__) + '/icon-mfa.svg']

    def id(self):
        return md_id

    def name(self):
        return md_name

    def description(self):
        return md_description

    def synopsis(self):
        return "account-name | command"

    def initialize(self):
        self.mfa = Mfa()

    def handleTriggerQuery(self, query):
        if not query.isValid:
            return

        tokens = query.string.split()

        if len(tokens) == 0:
            self.__list_mfa_actions(query, self.mfa.list_users())

        if len(tokens) == 1:
            self.__list_mfa_actions(query, [u for u in self.mfa.list_users() if
                                            u.startswith(tokens[0])])

        if len(tokens) == 0 or tokens[0] in ['a', 'ad', 'add']:
            item = Item(
                id='mfa-add',
                icon=self.icon_add,
                text='Add new account to 2fa',
                subtext='%s add account secret' % query.trigger.strip(),
                completion='%s add' % query.trigger.strip()
            )

            if len(tokens) == 1 and tokens[0] == 'add':
                item.completion = '%s add account secret' % query.trigger.strip()

            if len(tokens) == 3:
                item.completion = ''
                otp = self.mfa.try_generate(tokens[2])
                if not type(otp) == str:
                    item.subtext = 'Invalid secret'
                elif type(otp) == str:
                    item.subtext = 'Press Enter to add account'
                    item.actions = [Action('add', 'Press Enter to add account',
                                           lambda user=tokens[1], secret=tokens[
                                               2]: self.mfa.add(user, secret))]

            if len(tokens) >= 2 and tokens[1] in self.mfa.list_users():
                item.subtext = 'Account already exist'
                item.completion = ''
                item.actions = []

            query.add(item)

        if len(tokens) == 0 or tokens[0] in ['r', 're', 'rem', 'remo', 'remov',
                                             'remove']:
            item = Item(
                id='mfa-remove',
                icon=self.icon_remove,
                text='Remove an account from 2fs',
                subtext='%s remove account' % query.trigger.strip(),
                completion='%s remove' % query.trigger.strip()
            )

            if len(tokens) == 1 and tokens[0] == 'remove':
                item.completion = '%s remove account' % query.trigger.strip()

            if len(tokens) > 1:
                item.completion = ''
                if len([u for u in self.mfa.list_users() if
                        u.startswith(tokens[1])]) == 0:
                    item.subtext = 'Account not found'
                elif tokens[1] in self.mfa.list_users():
                    item.subtext = 'Press Enter to remove %s' % tokens[1]
                    item.actions = [
                        Action('remove', 'Press Enter to remove account',
                               lambda user=tokens[1]: self.mfa.remove(user))]

            query.add(item)

    def __list_mfa_actions(self, query, users):
        maxUsers = 5
        for user in users:
            if maxUsers == 0:
                break

            otp = self.mfa.generate(user)
            if not type(otp) == str and otp < 0:
                continue

            maxUsers -= 1
            query.add(Item(
                id='mfa-%s' % user,
                icon=self.icon_mfa,
                text='MFA for %s' % user,
                subtext=otp,
                completion='%s %s' % (query.trigger.strip(), user),
                actions=[Action('copy', 'Copy', setClipboardText(otp))]
            ))
