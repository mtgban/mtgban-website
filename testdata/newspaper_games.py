"""
The games the newspaper covers, and each one's names on TCGPlayer
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Game:
    # Value accepted by --games, and stored as tcgplayersalesmetadatamodel.game_name
    cli_name: str
    # TCGPlayer sitemap file stem: https://www.tcgplayer.com/sitemap/<sitemap_slug>.<n>.xml
    sitemap_slug: str
    # TCGPlayer productLineName, stored as tcgplayerproductinfomodel.game_name and read by the scoring SQL
    product_line_name: str


MAGIC = Game("Magic", "magic", "Magic: The Gathering")

# Every game mtgban prices (go-mtgban mtgban.AllGames). Both TCGPlayer names are matched exactly, so a
# neighbouring product line (e.g. "pokemon-japan" / "Pokemon Japan") is never picked up by accident.
GAMES: tuple[Game, ...] = (
    MAGIC,
    Game("Pokemon", "pokemon", "Pokemon"),
    Game("One-Piece", "one-piece-card-game", "One Piece Card Game"),
    Game("Yugioh", "yugioh", "YuGiOh"),
    Game(
        "Riftbound", "riftbound-league-of-legends-trading-card-game", "Riftbound: League of Legends Trading Card Game"
    ),
    Game("Lorcana", "lorcana-tcg", "Disney Lorcana"),
    Game("Flesh-and-Blood", "flesh-and-blood-tcg", "Flesh and Blood TCG"),
    Game("Gundam", "gundam-card-game", "Gundam Card Game"),
    Game("Palworld", "palworld-official-card-game", "Palworld OFFICIAL CARD GAME"),
)

ALL_GAMES: list[str] = [game.cli_name for game in GAMES]

_GAMES_BY_CLI_NAME: dict[str, Game] = {game.cli_name: game for game in GAMES}


def get_game(cli_name: str) -> Game:
    try:
        return _GAMES_BY_CLI_NAME[cli_name]
    except KeyError:
        raise ValueError(f"Unknown game {cli_name!r}; expected one of {ALL_GAMES}") from None
