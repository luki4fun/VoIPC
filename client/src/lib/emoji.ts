// The emoji the message box and the reaction picker offer. A reaction is
// checked as one emoji where it arrives (`isOneEmoji` in chat-rules.ts), so
// anything listed here must pass that: one grapheme, at most 32 bytes.

export const EMOJI_CATEGORIES: readonly { label: string; emojis: readonly string[] }[] = [
  { label: "Smileys", emojis: ["😀","😁","😂","🤣","😃","😄","😅","😆","😉","😊","😎","🤩","😏","😒","😞","😔","😟","😕","😣","😖","😫","😩","🥺","😢","😭","😤","😠","😡","🤬","😈","👿","💀","☠️","😱","😨","😰","😥","😓","🤗","🤔","🤭","🤫","🤥","😶","😐","😑","😬","🙄","😯","😧","😮","😲","🥱","😴","🤤","😷","🤒","🤕","🤢","🤮","🥴","😵","🤯","🥳","🥸","😇","🤠","🤡"] },
  { label: "Gestures", emojis: ["👋","🤚","🖐️","✋","🖖","👌","🤌","🤏","✌️","🤞","🤟","🤘","🤙","👈","👉","👆","👇","☝️","👍","👎","✊","👊","🤛","🤜","👏","🙌","👐","🤲","🤝","🙏","💪","🦾","🖕"] },
  { label: "Hearts", emojis: ["❤️","🧡","💛","💚","💙","💜","🖤","🤍","🤎","💔","❤️‍🔥","❤️‍🩹","💕","💞","💓","💗","💖","💘","💝","💟","♥️","😍","🥰","😘","😻"] },
  { label: "Objects", emojis: ["🔥","⭐","🌟","✨","💫","🎉","🎊","🎈","🎁","🏆","🥇","🎯","💡","💎","🔔","🎵","🎶","🎤","🎧","🎮","🕹️","📱","💻","⌨️","🖥️","📷","📸","🔒","🔑","🗝️","🛠️","⚙️","💣","🧨"] },
  { label: "Nature", emojis: ["🌈","☀️","🌤️","⛅","🌥️","☁️","🌧️","⛈️","🌩️","❄️","🌊","🌸","🌺","🌻","🌹","🌷","🌱","🌿","☘️","🍀","🍁","🍂","🌵","🌴","🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐸","🐵"] },
  { label: "Food", emojis: ["🍕","🍔","🍟","🌭","🍿","🧂","🥓","🍳","🥞","🧇","🧀","🍖","🍗","🥩","🌮","🌯","🍜","🍝","🍣","🍱","🍩","🍪","🎂","🍰","🧁","🍫","🍬","🍭","☕","🍵","🧃","🍺","🍻","🥂","🍷","🥃"] },
];

/** The few a message's reaction picker offers first. */
export const QUICK_REACTIONS: readonly string[] = ["👍", "❤️", "😂", "😮", "😢", "🎉"];

/**
 * `:name:` for each emoji above, as GitHub and Discord call them (a few under
 * two names): what the `:` completion and the picker's search find, and what
 * a typed `:joy:` becomes when it is sent (emote-rules.ts `tokenize`). Names
 * keep to a server emote's rule, `[a-z0-9_]{2,30}`.
 */
export const EMOJI_NAMES: Readonly<Record<string, string>> = {
  grinning: "😀", grin: "😁", joy: "😂", rofl: "🤣", smiley: "😃", smile: "😄", sweat_smile: "😅",
  laughing: "😆", satisfied: "😆", wink: "😉", blush: "😊", sunglasses: "😎", star_struck: "🤩",
  smirk: "😏", unamused: "😒", disappointed: "😞", pensive: "😔", worried: "😟", confused: "😕",
  persevere: "😣", confounded: "😖", tired_face: "😫", weary: "😩", pleading_face: "🥺", cry: "😢",
  sob: "😭", triumph: "😤", angry: "😠", rage: "😡", cursing_face: "🤬", smiling_imp: "😈",
  imp: "👿", skull: "💀", skull_and_crossbones: "☠️", scream: "😱", fearful: "😨", cold_sweat: "😰",
  disappointed_relieved: "😥", sweat: "😓", hugs: "🤗", hugging: "🤗", thinking: "🤔",
  hand_over_mouth: "🤭", shushing_face: "🤫", lying_face: "🤥", no_mouth: "😶", neutral_face: "😐",
  expressionless: "😑", grimacing: "😬", roll_eyes: "🙄", hushed: "😯", anguished: "😧",
  open_mouth: "😮", astonished: "😲", yawning_face: "🥱", sleeping: "😴", drooling_face: "🤤",
  mask: "😷", face_with_thermometer: "🤒", face_with_head_bandage: "🤕", nauseated_face: "🤢",
  vomiting_face: "🤮", woozy_face: "🥴", dizzy_face: "😵", exploding_head: "🤯", partying_face: "🥳",
  disguised_face: "🥸", innocent: "😇", cowboy_hat_face: "🤠", clown_face: "🤡",
  wave: "👋", raised_back_of_hand: "🤚", hand_splayed: "🖐️", raised_hand: "✋", hand: "✋",
  vulcan_salute: "🖖", ok_hand: "👌", pinched_fingers: "🤌", pinching_hand: "🤏", victory: "✌️",
  crossed_fingers: "🤞", love_you_gesture: "🤟", metal: "🤘", call_me_hand: "🤙", point_left: "👈",
  point_right: "👉", point_up_2: "👆", point_down: "👇", point_up: "☝️", thumbsup: "👍",
  thumbsdown: "👎", fist: "✊", punch: "👊", fist_left: "🤛", fist_right: "🤜", clap: "👏",
  raised_hands: "🙌", open_hands: "👐", palms_up_together: "🤲", handshake: "🤝", pray: "🙏",
  muscle: "💪", mechanical_arm: "🦾", middle_finger: "🖕",
  heart: "❤️", orange_heart: "🧡", yellow_heart: "💛", green_heart: "💚", blue_heart: "💙",
  purple_heart: "💜", black_heart: "🖤", white_heart: "🤍", brown_heart: "🤎", broken_heart: "💔",
  heart_on_fire: "❤️‍🔥", mending_heart: "❤️‍🩹", two_hearts: "💕", revolving_hearts: "💞",
  heartbeat: "💓", heartpulse: "💗", sparkling_heart: "💖", cupid: "💘", gift_heart: "💝",
  heart_decoration: "💟", hearts: "♥️", heart_eyes: "😍", smiling_face_with_hearts: "🥰",
  kissing_heart: "😘", heart_eyes_cat: "😻",
  fire: "🔥", star: "⭐", star2: "🌟", sparkles: "✨", dizzy: "💫", tada: "🎉", confetti_ball: "🎊",
  balloon: "🎈", gift: "🎁", trophy: "🏆", first_place_medal: "🥇", dart: "🎯", bulb: "💡",
  gem: "💎", bell: "🔔", musical_note: "🎵", notes: "🎶", microphone: "🎤", headphones: "🎧",
  video_game: "🎮", joystick: "🕹️", iphone: "📱", mobile_phone: "📱", computer: "💻",
  keyboard: "⌨️", desktop_computer: "🖥️", camera: "📷", camera_flash: "📸", lock: "🔒", key: "🔑",
  old_key: "🗝️", hammer_and_wrench: "🛠️", gear: "⚙️", bomb: "💣", firecracker: "🧨",
  rainbow: "🌈", sunny: "☀️", sun_behind_small_cloud: "🌤️", partly_sunny: "⛅",
  sun_behind_large_cloud: "🌥️", cloud: "☁️", cloud_with_rain: "🌧️",
  cloud_with_lightning_and_rain: "⛈️", cloud_with_lightning: "🌩️", snowflake: "❄️", ocean: "🌊",
  cherry_blossom: "🌸", hibiscus: "🌺", sunflower: "🌻", rose: "🌹", tulip: "🌷", seedling: "🌱",
  herb: "🌿", shamrock: "☘️", four_leaf_clover: "🍀", maple_leaf: "🍁", fallen_leaf: "🍂",
  cactus: "🌵", palm_tree: "🌴", dog: "🐶", cat: "🐱", mouse: "🐭", hamster: "🐹", rabbit: "🐰",
  fox_face: "🦊", bear: "🐻", panda_face: "🐼", frog: "🐸", monkey_face: "🐵",
  pizza: "🍕", hamburger: "🍔", fries: "🍟", hotdog: "🌭", popcorn: "🍿", salt: "🧂", bacon: "🥓",
  fried_egg: "🍳", pancakes: "🥞", waffle: "🧇", cheese: "🧀", meat_on_bone: "🍖",
  poultry_leg: "🍗", cut_of_meat: "🥩", taco: "🌮", burrito: "🌯", ramen: "🍜", spaghetti: "🍝",
  sushi: "🍣", bento: "🍱", doughnut: "🍩", cookie: "🍪", birthday: "🎂", cake: "🍰",
  cupcake: "🧁", chocolate_bar: "🍫", candy: "🍬", lollipop: "🍭", coffee: "☕", tea: "🍵",
  beverage_box: "🧃", beer: "🍺", beers: "🍻", clinking_glasses: "🥂", wine_glass: "🍷",
  tumbler_glass: "🥃",
};

/** An emoji's first name, for a tooltip or an aria-label. */
export const NAME_OF: ReadonlyMap<string, string> = new Map(
  Object.entries(EMOJI_NAMES)
    .reverse()
    .map(([name, e]) => [e, name]),
);
