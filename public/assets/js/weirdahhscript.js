let rgAPI = '/api/rg/v1/'
let raAPI = '/api/ra/v1/'

function routeToGame(game) {
    const encoded = __uv$config.prefix + __uv$config.encodeUrl(game.href)
    localStorage.setItem('url', encoded)
    window.location.href = '/q/'
}

function createGameCard(game) {
    const g = document.createElement('div')
    g.classList.add('g-icon')

    const imgButton = document.createElement('button')
    imgButton.type = 'button'

    const image = document.createElement('img')
    image.src = game.img
    image.alt = game.name

    const gname = document.createElement('p')
    gname.innerText = game.name

    imgButton.appendChild(image)
    g.appendChild(imgButton)
    g.appendChild(gname)

    g.addEventListener('click', () => routeToGame(game))
    imgButton.addEventListener('click', (event) => {
        event.preventDefault()
        event.stopPropagation()
        routeToGame(game)
    })

    return g
}

async function loadCards(endpoint, containerId) {
    const data = await fetch(endpoint)
        .then((response) => response.text())
        .then((text) => JSON.parse(text))

    const container = document.getElementById(containerId)
    data.forEach((game) => {
        container.appendChild(createGameCard(game))
    })
}

addEventListener('DOMContentLoaded', async () => {
    await loadCards(rgAPI, 'trendingg')
})

addEventListener('DOMContentLoaded', async () => {
    await loadCards(raAPI, 'trendinga')
})

function getRandomInt(min, max) {
    min = Math.ceil(min)
    max = Math.floor(max)
    return Math.floor(Math.random() * (max - min + 1)) + min
}

function getRandomLink() {
    let csites = [
        'https://google.com',
        'https://classroom.google.com',
        'https://docs.google.com',
        'https://nasa.gov',
        'https://desmos.com',
        'https://clever.com',
        'https://ixl.com',
    ]
    return csites[getRandomInt(0, csites.length - 1)]
}
function blank() {
    var currentUrl = top.location.href
    if (currentUrl === 'about:blank') {
        console.log(currentUrl)
    } else {
        var win = window.open()
        var url = '/'
        var iframe = win.document.createElement('iframe')
        top.location.replace(getRandomLink())
        iframe.style.position = 'fixed'
        iframe.style.top = 0
        iframe.style.bottom = 0
        iframe.style.left = 0
        iframe.style.right = 0
        iframe.style.border = 'none'
        iframe.style.outline = 'none'
        iframe.style.width = '100%'
        iframe.style.height = '100%'
        iframe.src = url

        win.document.body.appendChild(iframe)
    }
}

function search() {
    window.location.href = '/w/'
}
