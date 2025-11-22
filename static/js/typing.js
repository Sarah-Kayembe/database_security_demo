function typeText(id, messages, speed = 40, delayBetween = 600) {
    let element = document.getElementById(id);

    // Convert single string → array
    if (typeof messages === "string") {
        messages = [messages];
    }

    let msgIndex = 0;
    let charIndex = 0;

    function type() {
        if (msgIndex >= messages.length) return; // done

        let msg = messages[msgIndex];

        if (charIndex < msg.length) {
            element.innerHTML += msg.charAt(charIndex);
            charIndex++;
            setTimeout(type, speed);
        } else {
            // Finished this line → new line & next message
            element.innerHTML += "<br>";
            msgIndex++;
            charIndex = 0;
            setTimeout(type, delayBetween);
        }
    }

    type();
}

