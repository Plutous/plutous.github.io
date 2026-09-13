(() => {
  'use strict'

  const script = document.currentScript
  if (!script || !window.crypto || !window.crypto.subtle) return

  const manifestUrl = script.dataset.manifest
  const vaultUrl = script.dataset.vault
  const homeUrl = script.dataset.home || '/'
  const storageKey = `hidden-posts-key:${manifestUrl}`
  let envelopePromise
  let modal
  let afterUnlock

  const base64ToBytes = value => {
    const binary = atob(value)
    return Uint8Array.from(binary, character => character.charCodeAt(0))
  }

  const bytesToBase64 = value => {
    let binary = ''
    const bytes = new Uint8Array(value)
    bytes.forEach(byte => { binary += String.fromCharCode(byte) })
    return btoa(binary)
  }

  const getEnvelope = () => {
    if (!envelopePromise) {
      envelopePromise = fetch(manifestUrl, { cache: 'no-store' }).then(response => {
        if (!response.ok) throw new Error('无法读取隐藏文章数据')
        return response.json()
      })
    }
    return envelopePromise
  }

  const decrypt = async (payload, key) => {
    const plain = await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: base64ToBytes(payload.iv),
      tagLength: 128
    }, key, base64ToBytes(payload.data))
    return JSON.parse(new TextDecoder().decode(plain))
  }

  const importStoredKey = async () => {
    const encoded = sessionStorage.getItem(storageKey)
    if (!encoded) return null
    try {
      return await crypto.subtle.importKey(
        'raw',
        base64ToBytes(encoded),
        { name: 'AES-GCM' },
        true,
        ['decrypt']
      )
    } catch (_) {
      sessionStorage.removeItem(storageKey)
      return null
    }
  }

  const deriveKey = async (password, kdf) => {
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    )
    return crypto.subtle.deriveKey({
      name: 'PBKDF2',
      hash: kdf.hash,
      salt: base64ToBytes(kdf.salt),
      iterations: kdf.iterations
    }, passwordKey, { name: 'AES-GCM', length: 256 }, true, ['decrypt'])
  }

  const unlock = async password => {
    const envelope = await getEnvelope()
    const key = await deriveKey(password, envelope.kdf)
    const manifest = await decrypt(envelope.payload, key)
    const rawKey = await crypto.subtle.exportKey('raw', key)
    sessionStorage.setItem(storageKey, bytesToBase64(rawKey))
    return { key, manifest }
  }

  const getUnlocked = async () => {
    const key = await importStoredKey()
    if (!key) return null
    try {
      const envelope = await getEnvelope()
      return { key, manifest: await decrypt(envelope.payload, key) }
    } catch (_) {
      sessionStorage.removeItem(storageKey)
      return null
    }
  }

  const closeModal = () => {
    if (!modal) return
    modal.classList.remove('is-visible')
    document.body.classList.remove('hidden-posts-dialog-open')
    afterUnlock = null
  }

  const ensureModal = () => {
    if (modal) return modal
    modal = document.createElement('div')
    modal.id = 'hidden-posts-modal'
    modal.className = 'hidden-posts-modal'
    modal.setAttribute('aria-hidden', 'true')
    modal.innerHTML = `
      <div class="hidden-posts-dialog" role="dialog" aria-modal="true" aria-labelledby="hidden-posts-dialog-title">
        <button class="hidden-posts-dialog-close" type="button" aria-label="关闭"><i class="fas fa-times" aria-hidden="true"></i></button>
        <div class="hidden-posts-dialog-icon"><i class="fas fa-key" aria-hidden="true"></i></div>
        <h2 id="hidden-posts-dialog-title">打开隐藏文章</h2>
        <p>输入访问密码后，本次浏览会话内保持解锁。</p>
        <form>
          <label for="hidden-posts-password">访问密码</label>
          <input id="hidden-posts-password" name="password" type="password" autocomplete="current-password" required>
          <div class="hidden-posts-error" role="alert"></div>
          <button class="hidden-posts-submit" type="submit">解锁</button>
        </form>
      </div>`
    document.body.appendChild(modal)

    const form = modal.querySelector('form')
    const input = modal.querySelector('input')
    const error = modal.querySelector('.hidden-posts-error')
    const submit = modal.querySelector('.hidden-posts-submit')

    modal.addEventListener('click', event => {
      if (event.target === modal || event.target.closest('.hidden-posts-dialog-close')) closeModal()
    })
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && modal.classList.contains('is-visible')) closeModal()
    })
    form.addEventListener('submit', async event => {
      event.preventDefault()
      error.textContent = ''
      submit.disabled = true
      submit.textContent = '验证中…'
      try {
        const unlocked = await unlock(input.value)
        const callback = afterUnlock
        closeModal()
        input.value = ''
        if (callback) await callback(unlocked)
      } catch (_) {
        error.textContent = '密码不正确，请重新输入。'
        input.select()
      } finally {
        submit.disabled = false
        submit.textContent = '解锁'
      }
    })
    return modal
  }

  const openModal = callback => {
    const element = ensureModal()
    afterUnlock = callback
    element.classList.add('is-visible')
    element.setAttribute('aria-hidden', 'false')
    document.body.classList.add('hidden-posts-dialog-open')
    requestAnimationFrame(() => element.querySelector('input').focus())
  }

  const renderVault = manifest => {
    const vault = document.getElementById('hidden-posts-vault')
    if (!vault) return
    vault.innerHTML = ''

    const header = document.createElement('header')
    header.className = 'hidden-posts-vault-header'
    const description = document.createElement('p')
    description.textContent = `已解锁 ${manifest.posts.length} 篇隐藏文章，本次浏览会话内有效。`
    const lockButton = document.createElement('button')
    lockButton.type = 'button'
    lockButton.className = 'hidden-posts-lock-session'
    lockButton.innerHTML = '<i class="fas fa-lock" aria-hidden="true"></i> 退出私密模式'
    lockButton.addEventListener('click', () => {
      sessionStorage.removeItem(storageKey)
      window.location.href = homeUrl
    })
    header.append(description, lockButton)
    vault.appendChild(header)

    if (!manifest.posts.length) {
      const empty = document.createElement('p')
      empty.className = 'hidden-posts-empty'
      empty.textContent = '目前没有隐藏文章。'
      vault.appendChild(empty)
      return
    }

    const list = document.createElement('div')
    list.className = 'hidden-posts-list'
    manifest.posts.forEach(post => {
      const link = document.createElement('a')
      link.className = 'hidden-posts-card'
      link.href = post.url

      const title = document.createElement('span')
      title.className = 'hidden-posts-card-title'
      title.textContent = post.title
      const meta = document.createElement('span')
      meta.className = 'hidden-posts-card-meta'
      const labels = [...post.categories, ...post.tags]
      meta.textContent = labels.length ? `${post.date} · ${labels.join(' / ')}` : post.date
      const arrow = document.createElement('i')
      arrow.className = 'fas fa-arrow-right'
      arrow.setAttribute('aria-hidden', 'true')
      link.append(title, meta, arrow)
      list.appendChild(link)
    })
    vault.appendChild(list)
  }

  const ensureHeadingIds = headings => {
    const used = new Set(Array.from(document.querySelectorAll('[id]'), element => element.id))

    headings.forEach((heading, index) => {
      if (heading.id) return

      const base = heading.textContent.trim()
        .toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w\u4e00-\u9fff-]/g, '') || `private-heading-${index + 1}`
      let id = base
      let suffix = 2
      while (used.has(id)) id = `${base}-${suffix++}`
      heading.id = id
      used.add(id)
    })
  }

  const createTocList = (nodes, showNumber, prefix = []) => {
    const list = document.createElement('ol')
    list.className = prefix.length ? 'toc-child' : 'toc'

    nodes.forEach((node, index) => {
      const number = [...prefix, index + 1]
      const item = document.createElement('li')
      item.className = `toc-item toc-level-${node.level}`
      const link = document.createElement('a')
      link.className = 'toc-link'
      link.href = `#${encodeURI(node.heading.id)}`

      if (showNumber) {
        const numberElement = document.createElement('span')
        numberElement.className = 'toc-number'
        numberElement.textContent = `${number.join('.')}.`
        link.appendChild(numberElement)
      }

      const text = document.createElement('span')
      text.className = 'toc-text'
      text.textContent = node.heading.textContent.trim()
      link.appendChild(text)
      item.appendChild(link)
      if (node.children.length) item.appendChild(createTocList(node.children, showNumber, number))
      list.appendChild(item)
    })

    return list
  }

  const renderPostToc = (content, showNumber) => {
    const tocContent = document.querySelector('#card-toc .toc-content')
    if (!tocContent) return

    const headings = Array.from(content.querySelectorAll('h1,h2,h3,h4,h5,h6'))
    if (!headings.length) {
      const card = document.getElementById('card-toc')
      if (card) card.style.display = 'none'
      const mobileButton = document.getElementById('mobile-toc-button')
      if (mobileButton) mobileButton.style.display = 'none'
      return
    }

    ensureHeadingIds(headings)
    const roots = []
    const stack = []
    headings.forEach(heading => {
      const node = {
        heading,
        level: Number(heading.tagName.slice(1)),
        children: []
      }
      while (stack.length && stack[stack.length - 1].level >= node.level) stack.pop()
      if (stack.length) stack[stack.length - 1].children.push(node)
      else roots.push(node)
      stack.push(node)
    })

    tocContent.replaceChildren(createTocList(roots, showNumber !== false))
    tocContent.style.display = 'block'
  }

  const renderPost = async key => {
    const view = document.getElementById('hidden-post-view')
    const payloadElement = document.getElementById('hidden-post-payload')
    if (!view || !payloadElement) return

    const post = await decrypt(JSON.parse(payloadElement.textContent), key)
    view.innerHTML = ''

    const navigation = document.createElement('a')
    navigation.className = 'hidden-post-back'
    navigation.href = post.vaultUrl
    navigation.innerHTML = '<i class="fas fa-arrow-left" aria-hidden="true"></i> 返回隐藏文章'
    const date = document.createElement('time')
    date.className = 'hidden-post-date'
    date.textContent = post.date
    const content = document.createElement('article')
    content.className = 'hidden-post-content'
    content.innerHTML = post.content
    view.append(navigation, date, content)

    document.querySelectorAll('.page-title, .post-title, #site-title').forEach(element => {
      element.textContent = post.title
    })
    document.title = post.siteTitle ? `${post.title} | ${post.siteTitle}` : post.title
    renderPostToc(content, post.tocNumber)
    window.dispatchEvent(new CustomEvent('hexo-blog-decrypt'))
  }

  const initializePrivatePage = async () => {
    const vault = document.getElementById('hidden-posts-vault')
    const post = document.getElementById('hidden-post-view')
    if (!vault && !post) return

    const unlocked = await getUnlocked()
    if (unlocked) {
      if (vault) renderVault(unlocked.manifest)
      if (post) await renderPost(unlocked.key)
      return
    }

    openModal(async result => {
      if (vault) renderVault(result.manifest)
      if (post) await renderPost(result.key)
    })
  }

  const bindButton = () => {
    const button = document.getElementById('hidden-posts-button')
    if (!button || button.dataset.bound) return
    button.dataset.bound = 'true'
    button.addEventListener('click', async () => {
      const unlocked = await getUnlocked()
      if (unlocked) {
        window.location.href = unlocked.manifest.vaultUrl || vaultUrl
        return
      }
      openModal(result => {
        window.location.href = result.manifest.vaultUrl || vaultUrl
      })
    })
  }

  const init = () => {
    bindButton()
    initializePrivatePage().catch(() => {
      openModal(initializePrivatePage)
    })
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init)
  else init()
  document.addEventListener('pjax:complete', init)
})()
