import asyncio
import re
from datetime import datetime
from itertools import zip_longest
from typing import Optional, Union
from types import SimpleNamespace

import discord
from discord.ext import commands
from discord.ext.commands.cooldowns import BucketType
from discord.role import Role
from discord.utils import escape_markdown

from dateutil import parser
from natural.date import duration

from core import checks
from core.models import DMDisabled, PermissionLevel, SimilarCategoryConverter, getLogger
from core.paginator import EmbedPaginatorSession
from core.thread import Thread
from core.time import UserFriendlyTime, human_timedelta
from core.utils import *

logger = getLogger(__name__)


class Modmail(commands.Cog):
    """Commands directly related to Modmail functionality."""

    def __init__(self, bot):
        self.bot = bot
        
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

    @commands.group(aliases=["snippets"], invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet(self, ctx, *, name: str.lower = None):
        """
        Create pre-defined messages for use in threads.
        When `{prefix}snippet` is used by itself, this will retrieve
        a list of snippets that are currently set. `{prefix}snippet-name` will show what the
        snippet point to.
        To create a snippet:
        - `{prefix}snippet add snippet-name A pre-defined text.`
        You can use your snippet in a thread channel
        with `{prefix}snippet-name`, the message "A pre-defined text."
        will be sent to the recipient.
        Currently, there is not a built-in anonymous snippet command; however, a workaround
        is available using `{prefix}alias`. Here is how:
        - `{prefix}alias add snippet-name anonreply A pre-defined anonymous text.`
        See also `{prefix}alias`.
        """

        if name is not None:
            val = self.bot.snippets.get(name)
            if val is None:
                embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
            else:
                embed = discord.Embed(
                    title=f'Snippet - "{name}":', description=val, color=self.bot.main_color
                )
            return await ctx.send(embed=embed)

        if not self.bot.snippets:
            embed = discord.Embed(
                color=self.bot.error_color, description="You dont have any snippets at the moment."
            )
            embed.set_footer(text=f'Check "{self.bot.prefix}help snippet add" to add a snippet.')
            embed.set_author(name="Snippets", icon_url=ctx.guild.icon_url)
            return await ctx.send(embed=embed)

        embeds = []

        for i, names in enumerate(zip_longest(*(iter(sorted(self.bot.snippets)),) * 15)):
            description = format_description(i, names)
            embed = discord.Embed(color=self.bot.main_color, description=description)
            embed.set_author(name="Snippets", icon_url=ctx.guild.icon_url)
            embeds.append(embed)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @snippet.command(name="raw")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_raw(self, ctx, *, name: str.lower):
        """
        View the raw content of a snippet.
        """
        val = self.bot.snippets.get(name)
        if val is None:
            embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
        else:
            val = truncate(escape_code_block(val), 2048 - 7)
            embed = discord.Embed(
                title=f'Raw snippet - "{name}":',
                description=f"```\n{val}```",
                color=self.bot.main_color,
            )

        return await ctx.send(embed=embed)

    @snippet.command(name="add")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_add(self, ctx, name: str.lower, *, value: commands.clean_content):
        """
        Add a snippet.
        Simply to add a snippet, do: ```
        {prefix}snippet add hey hello there :)
        ```
        then when you type `{prefix}hey`, "hello there :)" will get sent to the recipient.
        To add a multi-word snippet name, use quotes: ```
        {prefix}snippet add "two word" this is a two word snippet.
        ```
        """
        if name in self.bot.snippets:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"Snippet `{name}` already exists.",
            )
            return await ctx.send(embed=embed)

        if name in self.bot.aliases:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"An alias that shares the same name exists: `{name}`.",
            )
            return await ctx.send(embed=embed)

        if len(name) > 120:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description="Snippet names cannot be longer than 120 characters.",
            )
            return await ctx.send(embed=embed)

        self.bot.snippets[name] = value
        await self.bot.config.update()

        embed = discord.Embed(
            title="Added snippet",
            color=self.bot.main_color,
            description="Successfully created snippet.",
        )
        return await ctx.send(embed=embed)

    @snippet.command(name="remove", aliases=["del", "delete"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_remove(self, ctx, *, name: str.lower):
        """Remove a snippet."""

        if name in self.bot.snippets:
            embed = discord.Embed(
                title="Removed snippet",
                color=self.bot.main_color,
                description=f"Snippet `{name}` is now deleted.",
            )
            self.bot.snippets.pop(name)
            await self.bot.config.update()
        else:
            embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
        await ctx.send(embed=embed)

    @snippet.command(name="edit")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_edit(self, ctx, name: str.lower, *, value):
        """
        Edit a snippet.
        To edit a multi-word snippet name, use quotes: ```
        {prefix}snippet edit "two word" this is a new two word snippet.
        ```
        """
        if name in self.bot.snippets:
            self.bot.snippets[name] = value
            await self.bot.config.update()

            embed = discord.Embed(
                title="Edited snippet",
                color=self.bot.main_color,
                description=f'`{name}` will now send "{value}".',
            )
        else:
            embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
        await ctx.send(embed=embed)

    @commands.command(usage="<category> [options]")
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @checks.thread_only()
    async def move(self, ctx, *, arguments):
        """
        Move a thread to another category.
        `category` may be a category ID, mention, or name.
        `options` is a string which takes in arguments on how to perform the move. Ex: "silently"
        """
        split_args = arguments.strip('"').split(" ")
        category = None

        # manually parse arguments, consumes as much of args as possible for category
        for i in range(len(split_args)):
            try:
                if i == 0:
                    fmt = arguments
                else:
                    fmt = " ".join(split_args[:-i])

                category = await SimilarCategoryConverter().convert(ctx, fmt)
            except commands.BadArgument:
                if i == len(split_args) - 1:
                    # last one
                    raise
                pass
            else:
                break

        if not category:
            raise commands.ChannelNotFound(arguments)

        options = " ".join(arguments.split(" ")[-i:])

        thread = ctx.thread
        silent = False

        if options:
            silent_words = ["silent", "silently"]
            silent = any(word in silent_words for word in options.split())

        await thread.channel.edit(category=category, sync_permissions=True)

        if self.bot.config["thread_move_notify"] and not silent:
            embed = discord.Embed(
                title=self.bot.config["thread_move_title"],
                description=self.bot.config["thread_move_response"],
                color=self.bot.main_color,
            )
            await thread.recipient.send(embed=embed)

        if self.bot.config["thread_move_notify_mods"]:
            mention = self.bot.config["mention"]
            await thread.channel.send(f"{mention}, thread has been moved.")

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    async def send_scheduled_close_message(self, ctx, after, silent=False):
        human_delta = human_timedelta(after.dt)

        silent = "*silently* " if silent else ""

        embed = discord.Embed(
            title="Scheduled close",
            description=f"This thread will close {silent}in {human_delta}.",
            color=self.bot.error_color,
        )

        if after.arg and not silent:
            embed.add_field(name="Message", value=after.arg)

        embed.set_footer(text="Closing will be cancelled if a thread message is sent.")
        embed.timestamp = after.dt

        await ctx.send(embed=embed)

    @commands.command(usage="[after] [close message]")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def close(self, ctx, *, after: UserFriendlyTime = None):
        """
        Close the current thread.
        Close after a period of time:
        - `{prefix}close in 5 hours`
        - `{prefix}close 2m30s`
        Custom close messages:
        - `{prefix}close 2 hours The issue has been resolved.`
        - `{prefix}close We will contact you once we find out more.`
        Silently close a thread (no message)
        - `{prefix}close silently`
        - `{prefix}close in 10m silently`
        Stop a thread from closing:
        - `{prefix}close cancel`
        """

        thread = ctx.thread

        now = datetime.utcnow()

        close_after = (after.dt - now).total_seconds() if after else 0
        message = after.arg if after else None
        silent = str(message).lower() in {"silent", "silently"}
        cancel = str(message).lower() == "cancel"

        if cancel:

            if thread.close_task is not None or thread.auto_close_task is not None:
                await thread.cancel_closure(all=True)
                embed = discord.Embed(
                    color=self.bot.error_color, description="Scheduled close has been cancelled."
                )
            else:
                embed = discord.Embed(
                    color=self.bot.error_color,
                    description="This thread has not already been scheduled to close.",
                )

            return await ctx.send(embed=embed)

        if after and after.dt > now:
            await self.send_scheduled_close_message(ctx, after, silent)

        await thread.close(closer=ctx.author, after=close_after, message=message, silent=silent)

    @staticmethod
    def parse_user_or_role(ctx, user_or_role):
        mention = None
        if user_or_role is None:
            mention = ctx.author.mention
        elif hasattr(user_or_role, "mention"):
            mention = user_or_role.mention
        elif user_or_role in {"here", "everyone", "@here", "@everyone"}:
            mention = "@" + user_or_role.lstrip("@")
        return mention

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def logs(self, ctx, *, user: User = None):
        """
        Get previous Modmail thread logs of a member.
        Leave `user` blank when this command is used within a
        thread channel to show logs for the current recipient.
        `user` may be a user ID, mention, or name.
        """

        await ctx.trigger_typing()

        if not user:
            thread = ctx.thread
            if not thread:
                raise commands.MissingRequiredArgument(SimpleNamespace(name="member"))
            user = thread.recipient

        default_avatar = "https://cdn.discordapp.com/embed/avatars/0.png"
        icon_url = getattr(user, "avatar_url", default_avatar)

        logs = await self.bot.api.get_user_logs(user.id)

        if not any(not log["open"] for log in logs):
            embed = discord.Embed(
                color=self.bot.error_color,
                description="This user does not have any previous logs.",
            )
            return await ctx.send(embed=embed)

        logs = reversed([log for log in logs if not log["open"]])

        embeds = self.format_log_embeds(logs, avatar_url=icon_url)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @logs.command(name="closed-by", aliases=["closeby"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def logs_closed_by(self, ctx, *, user: User = None):
        """
        Get all logs closed by the specified user.
        If no `user` is provided, the user will be the person who sent this command.
        `user` may be a user ID, mention, or name.
        """
        user = user if user is not None else ctx.author

        entries = await self.bot.api.search_closed_by(user.id)
        embeds = self.format_log_embeds(entries, avatar_url=self.bot.guild.icon_url)

        if not embeds:
            embed = discord.Embed(
                color=self.bot.error_color,
                description="No log entries have been found for that query.",
            )
            return await ctx.send(embed=embed)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @logs.command(name="delete", aliases=["wipe"])
    @checks.has_permissions(PermissionLevel.OWNER)
    async def logs_delete(self, ctx, key_or_link: str):
        """
        Wipe a log entry from the database.
        """
        key = key_or_link.split("/")[-1]

        success = await self.bot.api.delete_log_entry(key)

        if not success:
            embed = discord.Embed(
                title="Error",
                description=f"Log entry `{key}` not found.",
                color=self.bot.error_color,
            )
        else:
            embed = discord.Embed(
                title="Success",
                description=f"Log entry `{key}` successfully deleted.",
                color=self.bot.main_color,
            )

        await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def reply(self, ctx, *, msg: str = ""):
        """
        Reply to a Modmail thread.
        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message)

    @commands.command(aliases=["formatreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def freply(self, ctx, *, msg: str = ""):
        """
        Reply to a Modmail thread with variables.
        Works just like `{prefix}reply`, however with the addition of three variables:
          - `{{channel}}` - the `discord.TextChannel` object
          - `{{recipient}}` - the `discord.User` object of the recipient
          - `{{author}}` - the `discord.User` object of the author
        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        msg = self.bot.formatter.format(
            msg, channel=ctx.channel, recipient=ctx.thread.recipient, author=ctx.message.author
        )
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message)

    @commands.command(aliases=["anonreply", "anonymousreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def areply(self, ctx, *, msg: str = ""):
        """
        Reply to a thread anonymously.
        You can edit the anonymous user's name,
        avatar and tag using the config command.
        Edit the `anon_username`, `anon_avatar_url`
        and `anon_tag` config variables to do so.
        """
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, anonymous=True)

    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    async def selfcontact(self, ctx):
        """Creates a thread with yourself"""
        await ctx.invoke(self.contact, user=ctx.author)

    @commands.command(usage="<user> [category] [options]")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def contact(
        self,
        ctx,
        user: Union[discord.Member, discord.User],
        *,
        category: Union[SimilarCategoryConverter, str] = None,
        manual_trigger=True,
    ):
        """
        Create a thread with a specified member.
        If `category` is specified, the thread
        will be created in that specified category.
        `category`, if specified, may be a category ID, mention, or name.
        `user` may be a user ID, mention, or name.
        `options` can be `silent`
        """
        silent = False
        if isinstance(category, str):
            if "silent" in category or "silently" in category:
                silent = True
            category = None

        if user.bot:
            embed = discord.Embed(
                color=self.bot.error_color, description="Cannot start a thread with a bot."
            )
            return await ctx.send(embed=embed, delete_afer=3)

        exists = await self.bot.threads.find(recipient=user)
        if exists:
            embed = discord.Embed(
                color=self.bot.error_color,
                description="A thread for this user already "
                f"exists in {exists.channel.mention}.",
            )
            await ctx.channel.send(embed=embed, delete_after=3)

        else:
            thread = await self.bot.threads.create(user, creator=ctx.author, category=category)
            if self.bot.config["dm_disabled"] in (DMDisabled.NEW_THREADS, DMDisabled.ALL_THREADS):
                logger.info("Contacting user %s when Modmail DM is disabled.", user)

            if not silent and not self.bot.config.get("thread_contact_silently"):
                if ctx.author.id == user.id:
                    description = "You have opened a Modmail thread."
                else:
                    description = f"{ctx.author.name} has opened a Modmail thread."

                em = discord.Embed(
                    title="New Thread", description=description, color=self.bot.main_color,
                )
                if self.bot.config["show_timestamp"]:
                    em.timestamp = datetime.utcnow()
                em.set_footer(icon_url=ctx.author.avatar_url)
                await user.send(embed=em)

            embed = discord.Embed(
                title="Created Thread",
                description=f"Thread started by {ctx.author.mention} for {user.mention}.",
                color=self.bot.main_color,
            )
            await thread.wait_until_ready()
            await thread.channel.send(embed=embed)

            if manual_trigger:
                sent_emoji, _ = await self.bot.retrieve_emoji()
                await self.bot.add_reaction(ctx.message, sent_emoji)
                await asyncio.sleep(5)
                await ctx.message.delete()

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @trigger_typing
    async def blocked(self, ctx):
        """Retrieve a list of blocked users."""

        embeds = [discord.Embed(title="Blocked Users", color=self.bot.main_color, description="")]

        roles = []
        users = []

        for id_, reason in self.bot.blocked_users.items():
            user = self.bot.get_user(int(id_))
            if user:
                users.append((user.mention, reason))
            else:
                try:
                    user = await self.bot.fetch_user(id_)
                    users.append((user.mention, reason))
                except discord.NotFound:
                    users.append((id_, reason))

        for id_, reason in self.bot.blocked_roles.items():
            role = self.bot.guild.get_role(int(id_))
            if role:
                roles.append((role.mention, reason))

        if users:
            embed = embeds[0]

            for mention, reason in users:
                line = mention + f" - {reason or 'No Reason Provided'}\n"
                if len(embed.description) + len(line) > 2048:
                    embed = discord.Embed(
                        title="Blocked Users (Continued)",
                        color=self.bot.main_color,
                        description=line,
                    )
                    embeds.append(embed)
                else:
                    embed.description += line
        else:
            embeds[0].description = "Currently there are no blocked users."

        embeds.append(
            discord.Embed(title="Blocked Roles", color=self.bot.main_color, description="")
        )

        if roles:
            embed = embeds[-1]

            for mention, reason in roles:
                line = mention + f" - {reason or 'No Reason Provided'}\n"
                if len(embed.description) + len(line) > 2048:
                    embed = discord.Embed(
                        title="Blocked Roles (Continued)",
                        color=self.bot.main_color,
                        description=line,
                    )
                    embeds.append(embed)
                else:
                    embed.description += line
        else:
            embeds[-1].description = "Currently there are no blocked roles."

        session = EmbedPaginatorSession(ctx, *embeds)

        await session.run()

    @commands.command(usage="[user] [duration] [reason]")
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @trigger_typing
    async def block(
        self,
        ctx,
        user_or_role: Optional[Union[User, discord.Role]] = None,
        *,
        after: UserFriendlyTime = None,
    ):
        """
        Block a user from using Modmail.
        You may choose to set a time as to when the user will automatically be unblocked.
        Leave `user` blank when this command is used within a
        thread channel to block the current recipient.
        `user` may be a user ID, mention, or name.
        `duration` may be a simple "human-readable" time text. See `{prefix}help close` for examples.
        """

        if user_or_role is None:
            thread = ctx.thread
            if thread:
                user_or_role = thread.recipient
            elif after is None:
                raise commands.MissingRequiredArgument(SimpleNamespace(name="user"))
            else:
                raise commands.BadArgument(f'User "{after.arg}" not found.')

        mention = getattr(user_or_role, "mention", f"`{user_or_role.id}`")

        if (
            not isinstance(user_or_role, discord.Role)
            and str(user_or_role.id) in self.bot.blocked_whitelisted_users
        ):
            embed = discord.Embed(
                title="Error",
                description=f"Cannot block {mention}, user is whitelisted.",
                color=self.bot.error_color,
            )
            return await ctx.send(embed=embed)

        reason = f"by {escape_markdown(ctx.author.name)}#{ctx.author.discriminator}"

        if after is not None:
            if "%" in reason:
                raise commands.BadArgument('The reason contains illegal character "%".')
            if after.arg:
                reason += f" for `{after.arg}`"
            if after.dt > after.now:
                reason += f" until {after.dt.isoformat()}"

        reason += "."

        if isinstance(user_or_role, discord.Role):
            msg = self.bot.blocked_roles.get(str(user_or_role.id))
        else:
            msg = self.bot.blocked_users.get(str(user_or_role.id))

        if msg is None:
            msg = ""

        if msg:
            old_reason = msg.strip().rstrip(".")
            embed = discord.Embed(
                title="Success",
                description=f"{mention} was previously blocked {old_reason}.\n"
                f"{mention} is now blocked {reason}",
                color=self.bot.main_color,
            )
        else:
            embed = discord.Embed(
                title="Success",
                color=self.bot.main_color,
                description=f"{mention} is now blocked {reason}",
            )

        if isinstance(user_or_role, discord.Role):
            self.bot.blocked_roles[str(user_or_role.id)] = reason
        else:
            self.bot.blocked_users[str(user_or_role.id)] = reason
        await self.bot.config.update()

        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @trigger_typing
    async def unblock(self, ctx, *, user_or_role: Union[User, Role] = None):
        """
        Unblock a user from using Modmail.
        Leave `user` blank when this command is used within a
        thread channel to unblock the current recipient.
        `user` may be a user ID, mention, or name.
        """

        if user_or_role is None:
            thread = ctx.thread
            if thread:
                user_or_role = thread.recipient
            else:
                raise commands.MissingRequiredArgument(SimpleNamespace(name="user"))

        mention = getattr(user_or_role, "mention", f"`{user_or_role.id}`")
        name = getattr(user_or_role, "name", f"`{user_or_role.id}`")

        if (
            not isinstance(user_or_role, discord.Role)
            and str(user_or_role.id) in self.bot.blocked_users
        ):
            msg = self.bot.blocked_users.pop(str(user_or_role.id)) or ""
            await self.bot.config.update()

            if msg.startswith("System Message: "):
                # If the user is blocked internally (for example: below minimum account age)
                # Show an extended message stating the original internal message
                reason = msg[16:].strip().rstrip(".") or "no reason"
                embed = discord.Embed(
                    title="Success",
                    description=f"{mention} was previously blocked internally {reason}.\n"
                    f"{mention} is no longer blocked.",
                    color=self.bot.main_color,
                )
                embed.set_footer(
                    text="However, if the original system block reason still applies, "
                    f"{name} will be automatically blocked again. "
                    f'Use "{self.bot.prefix}blocked whitelist {user_or_role.id}" to whitelist the user.'
                )
            else:
                embed = discord.Embed(
                    title="Success",
                    color=self.bot.main_color,
                    description=f"{mention} is no longer blocked.",
                )
        elif (
            isinstance(user_or_role, discord.Role)
            and str(user_or_role.id) in self.bot.blocked_roles
        ):
            msg = self.bot.blocked_roles.pop(str(user_or_role.id)) or ""
            await self.bot.config.update()

            embed = discord.Embed(
                title="Success",
                color=self.bot.main_color,
                description=f"{mention} is no longer blocked.",
            )
        else:
            embed = discord.Embed(
                title="Error", description=f"{mention} is not blocked.", color=self.bot.error_color
            )

        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def delete(self, ctx, message_id: int = None):
        """
        Delete a message that was sent using the reply command.
        Deletes the previous message, unless a message ID is provided,
        which in that case, deletes the message with that message ID.
        Notes can only be deleted when a note ID is provided.
        """
        thread = ctx.thread

        try:
            await thread.delete_message(message_id, note=True)
        except ValueError as e:
            logger.warning("Failed to delete message: %s.", e)
            return await ctx.send(
                embed=discord.Embed(
                    title="Failed",
                    description="Cannot find a message to delete. Plain messages are not supported.",
                    color=self.bot.error_color,
                )
            )

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def enable(self, ctx):
        """
        Re-enables DM functionalities of Modmail.
        Undo's the `{prefix}disable` command, all DM will be relayed after running this command.
        """
        embed = discord.Embed(
            title="Success",
            description="Modmail will now accept all DM messages.",
            color=self.bot.main_color,
        )

        if self.bot.config["dm_disabled"] != DMDisabled.NONE:
            self.bot.config["dm_disabled"] = DMDisabled.NONE
            await self.bot.config.update()

        return await ctx.send(embed=embed)

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def disable(self, ctx):
        """
        Disable partial or full Modmail thread functions.
        To stop all new threads from being created, do `{prefix}disable new`.
        To stop all existing threads from DMing Modmail, do `{prefix}disable all`.
        To check if the DM function for Modmail is enabled, do `{prefix}isenable`.
        """
        await ctx.send_help(ctx.command)

    @disable.command(name="new")
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def disable_new(self, ctx):
        """
        Stop accepting new Modmail threads.
        No new threads can be created through DM.
        """
        embed = discord.Embed(
            title="Success",
            description="Modmail will not create any new threads.",
            color=self.bot.main_color,
        )
        if self.bot.config["dm_disabled"] < DMDisabled.NEW_THREADS:
            self.bot.config["dm_disabled"] = DMDisabled.NEW_THREADS
            await self.bot.config.update()

        return await ctx.send(embed=embed)

    @disable.command(name="all")
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def disable_all(self, ctx):
        """
        Disables all DM functionalities of Modmail.
        No new threads can be created through DM nor no further DM messages will be relayed.
        """
        embed = discord.Embed(
            title="Success",
            description="Modmail will not accept any DM messages.",
            color=self.bot.main_color,
        )

        if self.bot.config["dm_disabled"] != DMDisabled.ALL_THREADS:
            self.bot.config["dm_disabled"] = DMDisabled.ALL_THREADS
            await self.bot.config.update()

        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def isenable(self, ctx):
        """
        Check if the DM functionalities of Modmail is enabled.
        """

        if self.bot.config["dm_disabled"] == DMDisabled.NEW_THREADS:
            embed = discord.Embed(
                title="New Threads Disabled",
                description="Modmail is not creating new threads.",
                color=self.bot.error_color,
            )
        elif self.bot.config["dm_disabled"] == DMDisabled.ALL_THREADS:
            embed = discord.Embed(
                title="All DM Disabled",
                description="Modmail is not accepting any DM messages for new and existing threads.",
                color=self.bot.error_color,
            )
        else:
            embed = discord.Embed(
                title="Enabled",
                description="Modmail now is accepting all DM messages.",
                color=self.bot.main_color,
            )

        return await ctx.send(embed=embed)


def setup(bot):
    bot.add_cog(Modmail(bot))
