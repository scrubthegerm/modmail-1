import asyncio
import inspect
import os
import random
import re
from sys import stdout
import traceback
from contextlib import redirect_stdout
from datetime import datetime
from difflib import get_close_matches
from io import BytesIO, StringIO
from itertools import takewhile, zip_longest
from json import JSONDecodeError, loads
from subprocess import PIPE
from textwrap import indent
from types import SimpleNamespace
from typing import Union

import discord
from aiohttp import ClientResponseError
from discord.enums import ActivityType, Status
from discord.ext import commands, tasks
from discord.ext.commands.view import StringView
from pkg_resources import parse_version

from core import checks, utils
from core.changelog import Changelog
from core.models import (
    HostingMethod,
    InvalidConfigError,
    PermissionLevel,
    UnseenFormatter,
    getLogger,
)
from core.utils import trigger_typing, truncate
from core.paginator import EmbedPaginatorSession, MessagePaginatorSession


logger = getLogger(__name__)


class ModmailHelpCommand(commands.HelpCommand):
    async def command_callback(self, ctx, *, command=None):
        """Ovrwrites original command_callback to ensure `help` without any arguments
        returns with checks, `help all` returns without checks"""
        if command is None:
            self.verify_checks = True
        else:
            self.verify_checks = False

        if command == "all":
            command = None

        return await super().command_callback(ctx, command=command)

    async def format_cog_help(self, cog, *, no_cog=False):
        bot = self.context.bot
        prefix = self.clean_prefix

        formats = [""]
        for cmd in await self.filter_commands(
            cog.get_commands() if not no_cog else cog,
            sort=True,
            key=lambda c: (bot.command_perm(c.qualified_name), c.qualified_name),
        ):
            perm_level = bot.command_perm(cmd.qualified_name)
            if perm_level is PermissionLevel.INVALID:
                format_ = f"`{prefix + cmd.qualified_name}` "
            else:
                format_ = f"`[{perm_level}] {prefix + cmd.qualified_name}` "

            format_ += f"- {cmd.short_doc}\n" if cmd.short_doc else "- *No description.*\n"
            if not format_.strip():
                continue
            if len(format_) + len(formats[-1]) >= 1024:
                formats.append(format_)
            else:
                formats[-1] += format_

        embeds = []
        for format_ in formats:
            description = (
                cog.description or "No description."
                if not no_cog
                else "Miscellaneous commands without a category."
            )
            embed = discord.Embed(description=f"*{description}*", color=bot.main_color)

            if not format_:
                continue

            embed.add_field(name="Commands", value=format_ or "No commands.")

            continued = " (Continued)" if embeds else ""
            name = cog.qualified_name + " - Help" if not no_cog else "Miscellaneous Commands"
            embed.set_author(name=name + continued, icon_url=bot.user.avatar_url)

            embed.set_footer(
                text=f'Type "{prefix}{self.command_attrs["name"]} command" '
                "for more info on a specific command."
            )
            embeds.append(embed)
        return embeds

    def process_help_msg(self, help_: str):
        return help_.format(prefix=self.clean_prefix) if help_ else "No help message."

    async def send_bot_help(self, mapping):
        embeds = []
        no_cog_commands = sorted(mapping.pop(None), key=lambda c: c.qualified_name)
        cogs = sorted(mapping, key=lambda c: c.qualified_name)

        bot = self.context.bot

        # always come first
        default_cogs = [bot.get_cog("Modmail"), bot.get_cog("Utility"), bot.get_cog("Plugins")]

        default_cogs.extend(c for c in cogs if c not in default_cogs)

        for cog in default_cogs:
            embeds.extend(await self.format_cog_help(cog))
        if no_cog_commands:
            embeds.extend(await self.format_cog_help(no_cog_commands, no_cog=True))

        session = EmbedPaginatorSession(self.context, *embeds, destination=self.get_destination())
        return await session.run()

    async def send_cog_help(self, cog):
        embeds = await self.format_cog_help(cog)
        session = EmbedPaginatorSession(self.context, *embeds, destination=self.get_destination())
        return await session.run()

    async def _get_help_embed(self, topic):
        if not await self.filter_commands([topic]):
            return
        perm_level = self.context.bot.command_perm(topic.qualified_name)
        if perm_level is not PermissionLevel.INVALID:
            perm_level = f"{perm_level.name} [{perm_level}]"
        else:
            perm_level = "NONE"

        embed = discord.Embed(
            title=f"`{self.get_command_signature(topic)}`",
            color=self.context.bot.main_color,
            description=self.process_help_msg(topic.help),
        )
        return embed, perm_level

    async def send_command_help(self, command):
        topic = await self._get_help_embed(command)
        if topic is not None:
            topic[0].set_footer(text=f"Permission level: {topic[1]}")
            await self.get_destination().send(embed=topic[0])

    async def send_group_help(self, group):
        topic = await self._get_help_embed(group)
        if topic is None:
            return
        embed = topic[0]
        embed.add_field(name="Permission Level", value=topic[1], inline=False)

        format_ = ""
        length = len(group.commands)

        for i, command in enumerate(
            await self.filter_commands(group.commands, sort=True, key=lambda c: c.name)
        ):
            # BUG: fmt may run over the embed limit
            # TODO: paginate this
            if length == i + 1:  # last
                branch = "└─"
            else:
                branch = "├─"
            format_ += f"`{branch} {command.name}` - {command.short_doc}\n"

        embed.add_field(name="Sub Command(s)", value=format_[:1024], inline=False)
        embed.set_footer(
            text=f'Type "{self.clean_prefix}{self.command_attrs["name"]} command" '
            "for more info on a command."
        )

        await self.get_destination().send(embed=embed)

    async def send_error_message(self, error):
        command = self.context.kwargs.get("command")
        val = self.context.bot.snippets.get(command)
        if val is not None:
            embed = discord.Embed(
                title=f"{command} is a snippet.", color=self.context.bot.main_color
            )
            embed.add_field(name=f"`{command}` will send:", value=val)
            return await self.get_destination().send(embed=embed)

        val = self.context.bot.aliases.get(command)
        if val is not None:
            values = utils.parse_alias(val)

            if not values:
                embed = discord.Embed(
                    title="Error",
                    color=self.context.bot.error_color,
                    description=f"Alias `{command}` is invalid, this alias will now be deleted."
                    "This alias will now be deleted.",
                )
                embed.add_field(name=f"{command}` used to be:", value=val)
                self.context.bot.aliases.pop(command)
                await self.context.bot.config.update()
            else:
                if len(values) == 1:
                    embed = discord.Embed(
                        title=f"{command} is an alias.", color=self.context.bot.main_color
                    )
                    embed.add_field(name=f"`{command}` points to:", value=values[0])
                else:
                    embed = discord.Embed(
                        title=f"{command} is an alias.",
                        color=self.context.bot.main_color,
                        description=f"**`{command}` points to the following steps:**",
                    )
                    for i, val in enumerate(values, start=1):
                        embed.add_field(name=f"Step {i}:", value=val)

            embed.set_footer(
                text=f'Type "{self.clean_prefix}{self.command_attrs["name"]} alias" '
                "for more details on aliases."
            )
            return await self.get_destination().send(embed=embed)

        logger.warning("CommandNotFound: %s", error)

        embed = discord.Embed(color=self.context.bot.error_color)
        embed.set_footer(text=f'Command/Category "{command}" not found.')

        choices = set()

        for cmd in self.context.bot.walk_commands():
            if not cmd.hidden:
                choices.add(cmd.qualified_name)

        closest = get_close_matches(command, choices)
        if closest:
            embed.add_field(name="Perhaps you meant:", value="\n".join(f"`{x}`" for x in closest))
        else:
            embed.title = "Cannot find command or category"
            embed.set_footer(
                text=f'Type "{self.clean_prefix}{self.command_attrs["name"]}" '
                "for a list of all available commands."
            )
        await self.get_destination().send(embed=embed)


class Utility(commands.Cog):
    """General commands that provide utility."""

    def __init__(self, bot):
        self.bot = bot
        self._original_help_command = bot.help_command
        self.bot.help_command = ModmailHelpCommand(
            command_attrs={
                "help": "Shows this help message.",
                "checks": [checks.has_permissions_predicate(PermissionLevel.REGULAR)],
            },
        )
        self.bot.help_command.cog = self
        self.loop_presence.start()  # pylint: disable=no-member
        if not self.bot.config.get("enable_eval"):
            self.eval_.enabled = False
            logger.info("Eval disabled. enable_eval=False")

    def cog_unload(self):
        self.bot.help_command = self._original_help_command

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    @utils.trigger_typing
    async def ping(self, ctx):
        """Pong! Returns your websocket latency."""
        embed = discord.Embed(
            title="Pong! Websocket Latency:",
            description=f"{self.bot.ws.latency * 1000:.4f} ms",
            color=self.bot.main_color,
        )
        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def prefix(self, ctx, *, prefix=None):
        """
        Change the prefix of the bot.
        Type only `{prefix}prefix` to retrieve your current bot prefix.
        """

        current = self.bot.prefix
        embed = discord.Embed(
            title="Current prefix", color=self.bot.main_color, description=f"{current}"
        )

        if prefix is None:
            await ctx.send(embed=embed)
        else:
            embed.title = "Changed prefix!"
            embed.description = f"Set prefix to `{prefix}`"
            self.bot.config["prefix"] = prefix
            await self.bot.config.update()
            await ctx.send(embed=embed)

    @commands.group(aliases=["perms"], invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.OWNER)
    async def permissions(self, ctx):
        """
        Set the permissions for Modmail commands.
        You may set permissions based on individual command names, or permission
        levels.
        Acceptable permission levels are:
            - **Owner** [5] (absolute control over the bot)
            - **Administrator** [4] (administrative powers such as setting activities)
            - **Moderator** [3] (ability to block)
            - **Supporter** [2] (access to core Modmail supporting functions)
            - **Regular** [1] (most basic interactions such as help and about)
        By default, owner is set to the absolute bot owner and regular is `@everyone`.
        To set permissions, see `{prefix}help permissions add`; and to change permission level for specific
        commands see `{prefix}help permissions override`.
        Note: You will still have to manually give/take permission to the Modmail
        category to users/roles.
        """
        await ctx.send_help(ctx.command)

    @staticmethod
    def _verify_user_or_role(user_or_role):
        if isinstance(user_or_role, discord.Role):
            if user_or_role.is_default():
                return -1
        elif user_or_role in {"everyone", "all"}:
            return -1
        if hasattr(user_or_role, "id"):
            return user_or_role.id
        raise commands.BadArgument(f'User or Role "{user_or_role}" not found')

    @staticmethod
    def _parse_level(name):
        name = name.upper()
        try:
            return PermissionLevel[name]
        except KeyError:
            pass
        transform = {
            "1": PermissionLevel.REGULAR,
            "2": PermissionLevel.SUPPORTER,
            "3": PermissionLevel.MODERATOR,
            "4": PermissionLevel.ADMINISTRATOR,
            "5": PermissionLevel.OWNER,
        }
        return transform.get(name, PermissionLevel.INVALID)

    @permissions.command(name="override")
    @checks.has_permissions(PermissionLevel.OWNER)
    async def permissions_override(self, ctx, command_name: str.lower, *, level_name: str):
        """
        Change a permission level for a specific command.
        Examples:
        - `{prefix}perms override reply administrator`
        - `{prefix}perms override "plugin enabled" moderator`
        To undo a permission override, see `{prefix}help permissions remove`.
        Example:
        - `{prefix}perms remove override reply`
        - `{prefix}perms remove override plugin enabled`
        You can retrieve a single or all command level override(s), see`{prefix}help permissions get`.
        """

        command = self.bot.get_command(command_name)
        if command is None:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"The referenced command does not exist: `{command_name}`.",
            )
            return await ctx.send(embed=embed)

        level = self._parse_level(level_name)
        if level is PermissionLevel.INVALID:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"The referenced level does not exist: `{level_name}`.",
            )
        else:
            logger.info(
                "Updated command permission level for `%s` to `%s`.",
                command.qualified_name,
                level.name,
            )
            self.bot.config["override_command_level"][command.qualified_name] = level.name

            await self.bot.config.update()
            embed = discord.Embed(
                title="Success",
                color=self.bot.main_color,
                description="Successfully set command permission level for "
                f"`{command.qualified_name}` to `{level.name}`.",
            )
        return await ctx.send(embed=embed)

    @permissions.command(name="add", usage="[command/level] [name] [user/role]")
    @checks.has_permissions(PermissionLevel.OWNER)
    async def permissions_add(
        self,
        ctx,
        type_: str.lower,
        name: str,
        *,
        user_or_role: Union[discord.Role, utils.User, str],
    ):
        """
        Add a permission to a command or a permission level.
        For sub commands, wrap the complete command name with quotes.
        To find a list of permission levels, see `{prefix}help perms`.
        Examples:
        - `{prefix}perms add level REGULAR everyone`
        - `{prefix}perms add command reply @user`
        - `{prefix}perms add command "plugin enabled" @role`
        - `{prefix}perms add command help 984301093849028`
        Do not ping `@everyone` for granting permission to everyone, use "everyone" or "all" instead.
        """

        if type_ not in {"command", "level"}:
            return await ctx.send_help(ctx.command)

        command = level = None
        if type_ == "command":
            name = name.lower()
            command = self.bot.get_command(name)
            check = command is not None
        else:
            level = self._parse_level(name)
            check = level is not PermissionLevel.INVALID

        if not check:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"The referenced {type_} does not exist: `{name}`.",
            )
            return await ctx.send(embed=embed)

        value = self._verify_user_or_role(user_or_role)
        if type_ == "command":
            name = command.qualified_name
            await self.bot.update_perms(name, value)
        else:
            await self.bot.update_perms(level, value)
            name = level.name
            if level > PermissionLevel.REGULAR:
                if value == -1:
                    key = self.bot.modmail_guild.default_role
                elif isinstance(user_or_role, discord.Role):
                    key = user_or_role
                else:
                    key = self.bot.modmail_guild.get_member(value)
                if key is not None:
                    logger.info("Granting %s access to Modmail category.", key.name)
                    await self.bot.main_category.set_permissions(key, read_messages=True)

        embed = discord.Embed(
            title="Success",
            color=self.bot.main_color,
            description=f"Permission for `{name}` was successfully updated.",
        )
        return await ctx.send(embed=embed)

    @permissions.command(
        name="remove",
        aliases=["del", "delete", "revoke"],
        usage="[command/level] [name] [user/role] or [override] [command name]",
    )
    @checks.has_permissions(PermissionLevel.OWNER)
    async def permissions_remove(
        self,
        ctx,
        type_: str.lower,
        name: str,
        *,
        user_or_role: Union[discord.Role, utils.User, str] = None,
    ):
        """
        Remove permission to use a command, permission level, or command level override.
        For sub commands, wrap the complete command name with quotes.
        To find a list of permission levels, see `{prefix}help perms`.
        Examples:
        - `{prefix}perms remove level REGULAR everyone`
        - `{prefix}perms remove command reply @user`
        - `{prefix}perms remove command "plugin enabled" @role`
        - `{prefix}perms remove command help 984301093849028`
        - `{prefix}perms remove override block`
        - `{prefix}perms remove override "snippet add"`
        Do not ping `@everyone` for granting permission to everyone, use "everyone" or "all" instead.
        """
        if type_ not in {"command", "level", "override"} or (
            type_ != "override" and user_or_role is None
        ):
            return await ctx.send_help(ctx.command)

        if type_ == "override":
            extension = ctx.kwargs["user_or_role"]
            if extension is not None:
                name += f" {extension}"
            name = name.lower()
            name = getattr(self.bot.get_command(name), "qualified_name", name)
            level = self.bot.config["override_command_level"].get(name)
            if level is None:
                perm = self.bot.command_perm(name)
                embed = discord.Embed(
                    title="Error",
                    color=self.bot.error_color,
                    description=f"The command permission level was never overridden: `{name}`, "
                    f"current permission level is {perm.name}.",
                )
            else:
                logger.info("Restored command permission level for `%s`.", name)
                self.bot.config["override_command_level"].pop(name)
                await self.bot.config.update()
                perm = self.bot.command_perm(name)
                embed = discord.Embed(
                    title="Success",
                    color=self.bot.main_color,
                    description=f"Command permission level for `{name}` was successfully restored to {perm.name}.",
                )
            return await ctx.send(embed=embed)

        level = None
        if type_ == "command":
            name = name.lower()
            name = getattr(self.bot.get_command(name), "qualified_name", name)
        else:
            level = self._parse_level(name)
            if level is PermissionLevel.INVALID:
                embed = discord.Embed(
                    title="Error",
                    color=self.bot.error_color,
                    description=f"The referenced level does not exist: `{name}`.",
                )
                return await ctx.send(embed=embed)
            name = level.name

        value = self._verify_user_or_role(user_or_role)
        await self.bot.update_perms(level or name, value, add=False)

        if type_ == "level":
            if level > PermissionLevel.REGULAR:
                if value == -1:
                    logger.info("Denying @everyone access to Modmail category.")
                    await self.bot.main_category.set_permissions(
                        self.bot.modmail_guild.default_role, read_messages=False
                    )
                elif isinstance(user_or_role, discord.Role):
                    logger.info("Denying %s access to Modmail category.", user_or_role.name)
                    await self.bot.main_category.set_permissions(user_or_role, overwrite=None)
                else:
                    member = self.bot.modmail_guild.get_member(value)
                    if member is not None and member != self.bot.modmail_guild.me:
                        logger.info("Denying %s access to Modmail category.", member.name)
                        await self.bot.main_category.set_permissions(member, overwrite=None)

        embed = discord.Embed(
            title="Success",
            color=self.bot.main_color,
            description=f"Permission for `{name}` was successfully updated.",
        )
        return await ctx.send(embed=embed)

    def _get_perm(self, ctx, name, type_):
        if type_ == "command":
            permissions = self.bot.config["command_permissions"].get(name, [])
        else:
            permissions = self.bot.config["level_permissions"].get(name, [])
        if not permissions:
            embed = discord.Embed(
                title=f"Permission entries for {type_} `{name}`:",
                description="No permission entries found.",
                color=self.bot.main_color,
            )
        else:
            values = []
            for perm in permissions:
                if perm == -1:
                    values.insert(0, "**everyone**")
                    continue
                member = ctx.guild.get_member(perm)
                if member is not None:
                    values.append(member.mention)
                    continue
                user = self.bot.get_user(perm)
                if user is not None:
                    values.append(user.mention)
                    continue
                role = ctx.guild.get_role(perm)
                if role is not None:
                    values.append(role.mention)
                else:
                    values.append(str(perm))

            embed = discord.Embed(
                title=f"Permission entries for {type_} `{name}`:",
                description=", ".join(values),
                color=self.bot.main_color,
            )
        return embed

    @permissions.command(name="get", usage="[@user] or [command/level/override] [name]")
    @checks.has_permissions(PermissionLevel.OWNER)
    async def permissions_get(
        self, ctx, user_or_role: Union[discord.Role, utils.User, str], *, name: str = None
    ):
        """
        View the currently-set permissions.
        To find a list of permission levels, see `{prefix}help perms`.
        To view all command and level permissions:
        Examples:
        - `{prefix}perms get @user`
        - `{prefix}perms get 984301093849028`
        To view all users and roles of a command or level permission:
        Examples:
        - `{prefix}perms get command reply`
        - `{prefix}perms get command plugin remove`
        - `{prefix}perms get level SUPPORTER`
        To view command level overrides:
        Examples:
        - `{prefix}perms get override block`
        - `{prefix}perms get override permissions add`
        Do not ping `@everyone` for granting permission to everyone, use "everyone" or "all" instead.
        """

        if name is None and user_or_role not in {"command", "level", "override"}:
            value = str(self._verify_user_or_role(user_or_role))

            cmds = []
            levels = []

            done = set()
            command_permissions = self.bot.config["command_permissions"]
            level_permissions = self.bot.config["level_permissions"]
            for command in self.bot.walk_commands():
                if command not in done:
                    done.add(command)
                    permissions = command_permissions.get(command.qualified_name, [])
                    if value in permissions:
                        cmds.append(command.qualified_name)

            for level in PermissionLevel:
                permissions = level_permissions.get(level.name, [])
                if value in permissions:
                    levels.append(level.name)

            mention = getattr(user_or_role, "name", getattr(user_or_role, "id", user_or_role))
            desc_cmd = (
                ", ".join(map(lambda x: f"`{x}`", cmds))
                if cmds
                else "No permission entries found."
            )
            desc_level = (
                ", ".join(map(lambda x: f"`{x}`", levels))
                if levels
                else "No permission entries found."
            )

            embeds = [
                discord.Embed(
                    title=f"{mention} has permission with the following commands:",
                    description=desc_cmd,
                    color=self.bot.main_color,
                ),
                discord.Embed(
                    title=f"{mention} has permission with the following permission levels:",
                    description=desc_level,
                    color=self.bot.main_color,
                ),
            ]
        else:
            user_or_role = (user_or_role or "").lower()
            if user_or_role == "override":
                if name is None:
                    done = set()

                    overrides = {}
                    for command in self.bot.walk_commands():
                        if command not in done:
                            done.add(command)
                            level = self.bot.config["override_command_level"].get(
                                command.qualified_name
                            )
                            if level is not None:
                                overrides[command.qualified_name] = level

                    embeds = []
                    if not overrides:
                        embeds.append(
                            discord.Embed(
                                title="Permission Overrides",
                                description="You don't have any command level overrides at the moment.",
                                color=self.bot.error_color,
                            )
                        )
                    else:
                        for items in zip_longest(*(iter(sorted(overrides.items())),) * 15):
                            description = "\n".join(
                                ": ".join((f"`{name}`", level))
                                for name, level in takewhile(lambda x: x is not None, items)
                            )
                            embed = discord.Embed(
                                color=self.bot.main_color, description=description
                            )
                            embed.set_author(
                                name="Permission Overrides", icon_url=ctx.guild.icon_url
                            )
                            embeds.append(embed)

                    session = EmbedPaginatorSession(ctx, *embeds)
                    return await session.run()

                name = name.lower()
                name = getattr(self.bot.get_command(name), "qualified_name", name)
                level = self.bot.config["override_command_level"].get(name)
                perm = self.bot.command_perm(name)
                if level is None:
                    embed = discord.Embed(
                        title="Error",
                        color=self.bot.error_color,
                        description=f"The command permission level was never overridden: `{name}`, "
                        f"current permission level is {perm.name}.",
                    )
                else:
                    embed = discord.Embed(
                        title="Success",
                        color=self.bot.main_color,
                        description=f'Permission override for command "{name}" is "{perm.name}".',
                    )

                return await ctx.send(embed=embed)

            if user_or_role not in {"command", "level"}:
                return await ctx.send_help(ctx.command)
            embeds = []
            if name is not None:
                name = name.strip('"')
                command = level = None
                if user_or_role == "command":
                    name = name.lower()
                    command = self.bot.get_command(name)
                    check = command is not None
                else:
                    level = self._parse_level(name)
                    check = level is not PermissionLevel.INVALID

                if not check:
                    embed = discord.Embed(
                        title="Error",
                        color=self.bot.error_color,
                        description=f"The referenced {user_or_role} does not exist: `{name}`.",
                    )
                    return await ctx.send(embed=embed)

                if user_or_role == "command":
                    embeds.append(self._get_perm(ctx, command.qualified_name, "command"))
                else:
                    embeds.append(self._get_perm(ctx, level.name, "level"))
            else:
                if user_or_role == "command":
                    done = set()
                    for command in self.bot.walk_commands():
                        if command not in done:
                            done.add(command)
                            embeds.append(self._get_perm(ctx, command.qualified_name, "command"))
                else:
                    for perm_level in PermissionLevel:
                        embeds.append(self._get_perm(ctx, perm_level.name, "level"))

        session = EmbedPaginatorSession(ctx, *embeds)
        return await session.run()


def setup(bot):
    bot.add_cog(Utility(bot))
