/*
==========================================
SIEM-AI Owl Loader
==========================================
*/

document.addEventListener("DOMContentLoaded", async () => {

    const placeholder = document.getElementById("loader-placeholder");

    if (!placeholder) return;

    try {

        const response = await fetch("components/loader.html");

        const html = await response.text();

        placeholder.innerHTML = html;

        const owl = document.getElementById("loader-owl");
        const brand = document.querySelector(".loader-brand");
        const loader = document.getElementById("loader");

        // Owl appears

        setTimeout(() => {

            owl.classList.add("show-owl");

        }, 150);

        // Brand appears

        setTimeout(() => {

            brand.classList.add("show-brand");

        }, 950);

        // Loader disappears

        setTimeout(() => {

            loader.classList.add("hide-loader");

        }, 2500);

        // Remove from DOM

        setTimeout(() => {

            loader.remove();

        }, 3200);

    } catch (error) {

        console.error("Unable to load SIEM-AI loader.", error);

    }

});