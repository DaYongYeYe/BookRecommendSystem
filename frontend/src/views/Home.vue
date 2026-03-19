<template>

  
  <div class="selection:bg-amber-100">
    <!-- 1. 顶部导航栏 -->
    <nav class="glass-nav fixed top-0 w-full z-50">
      <div class="max-w-[1440px] mx-auto px-6 h-16 flex items-center justify-between">
        <div class="flex items-center gap-8">
          <a href="#" class="text-2xl font-bold serif tracking-tighter flex items-center gap-2">
            <span class="inline-block w-8 h-8 bg-black text-white text-center leading-8 rounded-sm">墨</span>
            雅筑
          </a>
          <div class="hidden md:flex gap-6 text-sm font-medium text-gray-600">
            <a href="#" class="hover:text-black transition-colors">书库精选</a>
            <a href="#" class="hover:text-black transition-colors">文学榜单</a>
            <a href="#" class="hover:text-black transition-colors">心境找书</a>
            <a href="#" class="hover:text-black transition-colors">出版前瞻</a>
          </div>
        </div>
        <p class="text-red-600 text-3xl font-bold">Tailwind 生效时这里是红色大字</p>
        <div class="flex-1 max-w-xl mx-8 relative hidden lg:block">
          <span class="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400">
            <span class="iconify" data-icon="hugeicons:search-02"></span>
          </span>
          <input
            type="text"
            class="w-full bg-gray-100 border-none rounded-full py-2 pl-12 pr-4 text-sm focus:ring-2 focus:ring-black transition-all"
            placeholder="搜索书名、作者、ISBN或题材关键词..."
          />
          <div class="absolute right-4 top-1/2 -translate-y-1/2 flex gap-2">
            <kbd class="bg-white px-1.5 py-0.5 rounded text-[10px] border shadow-sm text-gray-400">⌘</kbd>
            <kbd class="bg-white px-1.5 py-0.5 rounded text-[10px] border shadow-sm text-gray-400">K</kbd>
          </div>
        </div>
        <div class="flex items-center gap-5">
          <button class="text-gray-600 hover:text-black relative">
            <span class="iconify text-2xl" data-icon="hugeicons:notification-02"></span>
            <span class="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full border-2 border-white"></span>
          </button>
          <div class="h-8 w-[1px] bg-gray-200"></div>
          <div class="flex items-center gap-3 cursor-pointer group">
            <div class="text-right hidden sm:block">
              <p class="text-xs font-bold leading-none">林深见鹿</p>
              <p class="text-[10px] text-gray-400">书龄 1240天</p>
            </div>
            <img
              alt="User Avatar"
              class="w-10 h-10 rounded-full border-2 border-white shadow-sm ring-1 ring-gray-100"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/acd32cdbf04f4cd6b925d45113adee31.jpg"
            />
          </div>
        </div>
      </div>
    </nav>

    <!-- 2. Hero 区域 -->
    <section class="pt-32 pb-16 px-6 max-w-[1440px] mx-auto">
      <div
        class="relative overflow-hidden rounded-3xl bg-[#1A1A1A] text-white p-8 md:p-16 flex flex-col md:flex-row items-center gap-12"
      >
        <div class="flex-1 z-10">
          <span class="inline-block px-3 py-1 bg-amber-200 text-amber-900 text-xs font-bold rounded-full mb-6">
            2026年3月编辑评选
          </span>
          <h1 class="text-4xl md:text-6xl font-bold serif mb-6 leading-tight">
            在《漫长的余生》中<br />重构历史的涟漪
          </h1>
          <p class="text-lg text-gray-400 mb-8 max-w-xl leading-relaxed">
            罗新教授新作。这不是一部高头讲章式的史学著作，而是一位女性史家对命运、记忆与时间的深度注视。
          </p>
          <div class="flex flex-wrap gap-4">
            <button
              class="bg-white text-black px-8 py-4 rounded-full font-bold flex items-center gap-2 hover:bg-amber-50 transition-colors shadow-lg shadow-white/10"
            >
              <span class="iconify" data-icon="hugeicons:book-open-01"></span>
              立即试读
            </button>
            <button class="border border-white/20 hover:bg-white/10 px-8 py-4 rounded-full font-bold transition-all">
              加入书架
            </button>
          </div>
          <div class="mt-12 flex items-center gap-8">
            <div>
              <p class="text-2xl font-bold">9.4</p>
              <p class="text-xs text-gray-500 uppercase tracking-widest">综合评分</p>
            </div>
            <div>
              <p class="text-2xl font-bold">128k+</p>
              <p class="text-xs text-gray-500 uppercase tracking-widest">近期阅读</p>
            </div>
          </div>
        </div>
        <div class="relative w-64 md:w-80">
          <img
            alt="Featured Book Cover"
            class="w-full rounded shadow-2xl shadow-black transform rotate-3 hover:rotate-0 transition-transform duration-500"
            src="https://modao.cc/agent-py/media/generated_images/2026-03-16/4919ab94bab74cf1a55f48d8c43f120d.jpg"
          />
          <div
            class="absolute -bottom-4 -right-4 w-24 h-24 bg-amber-400 rounded-full flex items-center justify-center text-black text-center font-bold text-xs p-2 leading-tight"
          >
            HOT TOP 1
          </div>
        </div>
      </div>
    </section>

    <!-- 3. 按心境筛选 -->
    <section class="px-6 mb-16 max-w-[1440px] mx-auto">
      <div class="flex items-center justify-between mb-8">
        <h2 class="text-xl font-bold flex items-center gap-2">
          <span class="iconify text-amber-500" data-icon="hugeicons:sparkles"></span>
          此刻，你的阅读心境是？
        </h2>
      </div>
      <div class="flex gap-4 overflow-x-auto pb-4 custom-scroll">
        <button
          class="flex-shrink-0 px-6 py-3 rounded-2xl bg-white border border-gray-100 shadow-sm hover:border-black transition-all flex items-center gap-3"
        >
          <span class="iconify text-blue-400" data-icon="hugeicons:cloud-01"></span>
          <span class="font-medium">寻求治愈</span>
        </button>
        <button
          class="flex-shrink-0 px-6 py-3 rounded-2xl bg-white border border-gray-100 shadow-sm hover:border-black transition-all flex items-center gap-3"
        >
          <span class="iconify text-purple-400" data-icon="hugeicons:flash"></span>
          <span class="font-medium">脑力风暴</span>
        </button>
        <button
          class="flex-shrink-0 px-6 py-3 rounded-2xl bg-white border border-gray-100 shadow-sm hover:border-black transition-all flex items-center gap-3"
        >
          <span class="iconify text-orange-400" data-icon="hugeicons:sun-03"></span>
          <span class="font-medium">热血澎湃</span>
        </button>
        <button
          class="flex-shrink-0 px-6 py-3 rounded-2xl bg-white border border-gray-100 shadow-sm hover:border-black transition-all flex items-center gap-3"
        >
          <span class="iconify text-green-400" data-icon="hugeicons:leaf"></span>
          <span class="font-medium">自然探索</span>
        </button>
        <button
          class="flex-shrink-0 px-6 py-3 rounded-2xl bg-white border border-gray-100 shadow-sm hover:border-black transition-all flex items-center gap-3"
        >
          <span class="iconify text-indigo-400" data-icon="hugeicons:moon-02"></span>
          <span class="font-medium">深夜沉思</span>
        </button>
        <button
          class="flex-shrink-0 px-6 py-3 rounded-2xl bg-white border border-gray-100 shadow-sm hover:border-black transition-all flex items-center gap-3"
        >
          <span class="iconify text-rose-400" data-icon="hugeicons:heart-pushed"></span>
          <span class="font-medium">细腻情感</span>
        </button>
        <button
          class="flex-shrink-0 px-6 py-3 rounded-2xl bg-white border border-gray-100 shadow-sm hover:border-black transition-all flex items-center gap-3"
        >
          <span class="iconify text-gray-400" data-icon="hugeicons:align-bottom"></span>
          <span class="font-medium">硬核逻辑</span>
        </button>
      </div>
    </section>

    <!-- 4. 个性化推荐与榜单 -->
    <section class="px-6 mb-16 max-w-[1440px] mx-auto grid grid-cols-1 lg:grid-cols-4 gap-12">
      <!-- 猜你喜欢 -->
      <div class="lg:col-span-3">
        <div class="flex items-center justify-between mb-8">
          <h3 class="text-2xl serif font-bold">为你定制</h3>
          <a
            href="#"
            class="text-sm text-gray-500 flex items-center gap-1 hover:text-black transition-colors"
          >
            查看全部 <span class="iconify" data-icon="hugeicons:arrow-right-01"></span>
          </a>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-8">
          <!-- Book Item 1 -->
          <div class="group cursor-pointer">
            <div
              class="relative aspect-[3/4] mb-4 overflow-hidden rounded-lg shadow-md book-card transition-all duration-300"
            >
              <img
                alt="Book Cover 1"
                class="w-full h-full object-cover"
                src="https://modao.cc/agent-py/media/generated_images/2026-03-16/c4c23bbec05f4000ae33410901a83720.jpg"
              />
              <div
                class="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-4"
              >
                <button class="p-3 bg-white rounded-full">
                  <span class="iconify" data-icon="hugeicons:bookmark-02"></span>
                </button>
                <button class="p-3 bg-white rounded-full">
                  <span class="iconify" data-icon="hugeicons:view-off"></span>
                </button>
              </div>
            </div>
            <h4 class="font-bold text-sm mb-1 line-clamp-1">夜晚的潜水艇</h4>
            <p class="text-xs text-gray-500 mb-2">陈春成</p>
            <div class="flex items-center gap-1 text-amber-500 text-[10px]">
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="ml-1 text-gray-400 font-medium">9.1</span>
            </div>
          </div>

          <!-- Book Item 2 -->
          <div class="group cursor-pointer">
            <div
              class="relative aspect-[3/4] mb-4 overflow-hidden rounded-lg shadow-md book-card transition-all duration-300"
            >
              <img
                alt="Book Cover 2"
                class="w-full h-full object-cover"
                src="https://modao.cc/agent-py/media/generated_images/2026-03-16/11afde95e43e4f91a15455e9f87c4411.jpg"
              />
            </div>
            <h4 class="font-bold text-sm mb-1 line-clamp-1">芯片战争：争夺核心技术</h4>
            <p class="text-xs text-gray-500 mb-2">克里斯·米勒</p>
            <div class="flex items-center gap-1 text-amber-500 text-[10px]">
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify text-gray-200" data-icon="hugeicons:star"></span>
              <span class="ml-1 text-gray-400 font-medium">8.8</span>
            </div>
          </div>

          <!-- Book Item 3 -->
          <div class="group cursor-pointer">
            <div
              class="relative aspect-[3/4] mb-4 overflow-hidden rounded-lg shadow-md book-card transition-all duration-300"
            >
              <img
                alt="Book Cover 3"
                class="w-full h-full object-cover"
                src="https://modao.cc/agent-py/media/generated_images/2026-03-16/b9fa6d67b3654a71b2f4c30370480c35.jpg"
              />
            </div>
            <h4 class="font-bold text-sm mb-1 line-clamp-1">克拉拉与太阳</h4>
            <p class="text-xs text-gray-500 mb-2">石黑一雄</p>
            <div class="flex items-center gap-1 text-amber-500 text-[10px]">
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="ml-1 text-gray-400 font-medium">9.3</span>
            </div>
          </div>

          <!-- Book Item 4 -->
          <div class="group cursor-pointer">
            <div
              class="relative aspect-[3/4] mb-4 overflow-hidden rounded-lg shadow-md book-card transition-all duration-300"
            >
              <img
                alt="Book Cover 4"
                class="w-full h-full object-cover"
                src="https://modao.cc/agent-py/media/generated_images/2026-03-16/31f26d5f19ae496192e94f400ef2f719.jpg"
              />
            </div>
            <h4 class="font-bold text-sm mb-1 line-clamp-1">消失的艺术</h4>
            <p class="text-xs text-gray-500 mb-2">路内</p>
            <div class="flex items-center gap-1 text-amber-500 text-[10px]">
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify" data-icon="hugeicons:star"></span>
              <span class="iconify text-gray-200" data-icon="hugeicons:star"></span>
              <span class="ml-1 text-gray-400 font-medium">8.2</span>
            </div>
          </div>

          <!-- Row 2 占位 -->
          <div class="group cursor-pointer">
            <div
              class="relative aspect-[3/4] mb-4 overflow-hidden rounded-lg shadow-md book-card transition-all duration-300 text-center flex flex-col items-center justify-center border-2 border-dashed border-gray-200 hover:border-black transition-colors"
            >
              <span
                class="iconify text-3xl text-gray-300 mb-2"
                data-icon="hugeicons:add-01"
              ></span>
              <span class="text-xs text-gray-400 font-medium">发现更多惊喜</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 侧边榜单 -->
      <div>
        <div class="flex items-center justify-between mb-8">
          <h3 class="text-xl serif font-bold">高分口碑榜</h3>
          <span class="iconify text-gray-300" data-icon="hugeicons:chart-bar-01"></span>
        </div>
        <div class="space-y-6">
          <div class="flex items-center gap-4 group cursor-pointer">
            <span class="text-2xl font-black text-gray-200 group-hover:text-amber-500 transition-colors">01</span>
            <img
              alt="Rank 1"
              class="w-12 h-16 rounded shadow-sm"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/9bf13d2def4f4874a90d0747ba28f3bd.jpg"
            />
            <div class="flex-1">
              <h5 class="text-sm font-bold leading-none mb-1">额尔古纳河右岸</h5>
              <p class="text-[10px] text-gray-400">迟子建 · 12.4w人评价</p>
            </div>
          </div>
          <div class="flex items-center gap-4 group cursor-pointer">
            <span class="text-2xl font-black text-gray-200 group-hover:text-amber-500 transition-colors">02</span>
            <img
              alt="Rank 2"
              class="w-12 h-16 rounded shadow-sm"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/3c7d0e93b63649b3a9aba1700a03becc.jpg"
            />
            <div class="flex-1">
              <h5 class="text-sm font-bold leading-none mb-1">置身事内</h5>
              <p class="text-[10px] text-gray-400">兰小欢 · 9.8w人评价</p>
            </div>
          </div>
          <div class="flex items-center gap-4 group cursor-pointer">
            <span class="text-2xl font-black text-gray-200 group-hover:text-amber-500 transition-colors">03</span>
            <img
              alt="Rank 3"
              class="w-12 h-16 rounded shadow-sm"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/2c21f2b387b449df95c85d60ba645df4.jpg"
            />
            <div class="flex-1">
              <h5 class="text-sm font-bold leading-none mb-1">长安的荔枝</h5>
              <p class="text-[10px] text-gray-400">马伯庸 · 8.1w人评价</p>
            </div>
          </div>
          <div class="flex items-center gap-4 group cursor-pointer">
            <span class="text-2xl font-black text-gray-200 group-hover:text-amber-500 transition-colors">04</span>
            <img
              alt="Rank 4"
              class="w-12 h-16 rounded shadow-sm"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/895dee6118de4ce8bae3395a2175d48b.jpg"
            />
            <div class="flex-1">
              <h5 class="text-sm font-bold leading-none mb-1">局外人</h5>
              <p class="text-[10px] text-gray-400">阿尔贝·加缪 · 7.2w人评价</p>
            </div>
          </div>
        </div>

        <div class="mt-12 bg-gray-100 rounded-2xl p-6">
          <h6 class="font-bold text-sm mb-4 flex items-center gap-2">
            <span class="iconify text-amber-600" data-icon="hugeicons:gift"></span>
            本周读书任务
          </h6>
          <div class="space-y-3">
            <div class="flex items-center justify-between text-xs">
              <span class="text-gray-500">阅读进度 (3/5)</span>
              <span class="font-bold">60%</span>
            </div>
            <div class="w-full bg-gray-200 h-1.5 rounded-full overflow-hidden">
              <div class="bg-black h-full w-[60%]"></div>
            </div>
            <p class="text-[10px] text-gray-400">完成后可领取「春季限定书签」</p>
          </div>
        </div>
      </div>
    </section>

    <!-- 5. 沉浸式分类网格 -->
    <section class="bg-gray-50 py-20 px-6">
      <div class="max-w-[1440px] mx-auto">
        <div class="flex flex-col md:flex-row md:items-end justify-between mb-12 gap-6">
          <div>
            <h3 class="text-3xl font-bold serif mb-4">全维度探索</h3>
            <p class="text-gray-500">20+ 细分题材，在这里发现每一个独特的灵魂坐标</p>
          </div>
          <div class="flex gap-2">
            <button class="p-2 border rounded-full hover:bg-white transition-all">
              <span class="iconify" data-icon="hugeicons:arrow-left-01"></span>
            </button>
            <button class="p-2 border rounded-full hover:bg-white transition-all">
              <span class="iconify" data-icon="hugeicons:arrow-right-01"></span>
            </button>
          </div>
        </div>

        <div class="grid grid-cols-2 lg:grid-cols-4 gap-6">
          <div class="relative h-64 rounded-2xl overflow-hidden group cursor-pointer">
            <img
              alt="Category Sci-Fi"
              class="absolute inset-0 w-full h-full object-cover transition-transform duration-700 group-hover:scale-110"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/79f338a5044345c5ab1c8b2fdc98781f.jpg"
            />
            <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent"></div>
            <div class="absolute bottom-6 left-6 text-white text-left">
              <p class="text-xs uppercase tracking-widest opacity-60 mb-1">Sci-Fi</p>
              <h4 class="text-xl font-bold">赛博民俗</h4>
              <p class="text-xs opacity-0 group-hover:opacity-100 transition-opacity mt-2">
                当芯片遇见古老传说 →
              </p>
            </div>
          </div>

          <div class="relative h-64 rounded-2xl overflow-hidden group cursor-pointer">
            <img
              alt="Category History"
              class="absolute inset-0 w-full h-full object-cover transition-transform duration-700 group-hover:scale-110"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/d423e5ad9aac456a8ee8f959da839d01.jpg"
            />
            <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent"></div>
            <div class="absolute bottom-6 left-6 text-white text-left">
              <p class="text-xs uppercase tracking-widest opacity-60 mb-1">Geography</p>
              <h4 class="text-xl font-bold">地理叙事</h4>
              <p class="text-xs opacity-0 group-hover:opacity-100 transition-opacity mt-2">
                行走在大地上的文字 →
              </p>
            </div>
          </div>

          <div class="relative h-64 rounded-2xl overflow-hidden group cursor-pointer">
            <img
              alt="Category Arts"
              class="absolute inset-0 w-full h-full object-cover transition-transform duration-700 group-hover:scale-110"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/ca76d47260d4409da71020b9cb9fb40e.jpg"
            />
            <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent"></div>
            <div class="absolute bottom-6 left-6 text-white text-left">
              <p class="text-xs uppercase tracking-widest opacity-60 mb-1">Folklore</p>
              <h4 class="text-xl font-bold">手稿复原</h4>
              <p class="text-xs opacity-0 group-hover:opacity-100 transition-opacity mt-2">
                跨越时空的笔迹温存 →
              </p>
            </div>
          </div>

          <div class="relative h-64 rounded-2xl overflow-hidden group cursor-pointer">
            <img
              alt="Category Mystery"
              class="absolute inset-0 w-full h-full object-cover transition-transform duration-700 group-hover:scale-110"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/6a5a5e6ce27340a5aa4a07fdedd5c6fd.jpg"
            />
            <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent"></div>
            <div class="absolute bottom-6 left-6 text-white text-left">
              <p class="text-xs uppercase tracking-widest opacity-60 mb-1">Social</p>
              <h4 class="text-xl font-bold">方言小说</h4>
              <p class="text-xs opacity-0 group-hover:opacity-100 transition-opacity mt-2">
                最地道的草根生命力 →
              </p>
            </div>
          </div>
        </div>

        <div class="mt-12 flex justify-center">
          <div class="flex flex-wrap items-center justify-center gap-2 max-w-3xl">
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >硬核推理</span
            >
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >女性主义</span
            >
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >环境史</span
            >
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >后启示录</span
            >
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >人工智能理论</span
            >
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >唐诗美学</span
            >
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >现代医学</span
            >
            <span
              class="px-3 py-1 bg-white border rounded-full text-xs text-gray-500 hover:border-black cursor-pointer transition-colors"
              >更多题材 (18+)</span
            >
          </div>
        </div>
      </div>
    </section>

    <!-- 6. 用户社交广场 -->
    <section class="py-20 px-6 max-w-[1440px] mx-auto">
      <div class="text-center mb-16">
        <h3 class="text-3xl font-bold serif mb-4 underline-offset-8 decoration-amber-300 decoration-4">
          读者共鸣时刻
        </h3>
        <p class="text-gray-500">每一本书都是跨越时空的会面</p>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <!-- Review 1 -->
        <div class="p-8 bg-white border border-gray-100 rounded-3xl shadow-sm hover:shadow-xl transition-shadow group">
          <div class="flex items-center gap-3 mb-6">
            <img
              alt="Review User"
              class="w-10 h-10 rounded-full object-cover"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/33197687e1cd42adbbc443b37811ad63.jpg"
            />
            <div>
              <p class="text-sm font-bold">木心追随者</p>
              <p class="text-[10px] text-gray-400">点评了《文学回忆录》</p>
            </div>
          </div>
          <p class="text-sm leading-relaxed text-gray-600 mb-6 italic">
            “读这本书就像是在听一位老者在烛光下缓缓讲述，那些已故的大师仿佛又活了过来。不仅是文学，更是人生观的重塑。”
          </p>
          <div class="flex items-center justify-between">
            <div class="flex gap-4">
              <button
                class="flex items-center gap-1 text-xs text-gray-400 hover:text-red-500 transition-colors"
              >
                <span class="iconify" data-icon="hugeicons:favourite"></span>
                1.2k
              </button>
              <button
                class="flex items-center gap-1 text-xs text-gray-400 hover:text-blue-500 transition-colors"
              >
                <span class="iconify" data-icon="hugeicons:comment-01"></span>
                82
              </button>
            </div>
            <span class="text-[10px] text-gray-300">2026-03-15</span>
          </div>
        </div>

        <!-- Review 2 -->
        <div class="p-8 bg-white border border-gray-100 rounded-3xl shadow-sm hover:shadow-xl transition-shadow group">
          <div class="flex items-center gap-3 mb-6">
            <img
              alt="Review User"
              class="w-10 h-10 rounded-full object-cover"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/33197687e1cd42adbbc443b37811ad63.jpg"
            />
            <div>
              <p class="text-sm font-bold">赛博隐士</p>
              <p class="text-[10px] text-gray-400">点评了《呼吸》</p>
            </div>
          </div>
          <p class="text-sm leading-relaxed text-gray-600 mb-6 italic">
            “特德·姜对科学逻辑的浪漫化处理简直无与伦比。那个关于时间旅行和自由意志的段落我反复读了三遍。”
          </p>
          <div class="flex items-center justify-between">
            <div class="flex gap-4">
              <button
                class="flex items-center gap-1 text-xs text-gray-400 hover:text-red-500 transition-colors"
              >
                <span class="iconify" data-icon="hugeicons:favourite"></span>
                856
              </button>
              <button
                class="flex items-center gap-1 text-xs text-gray-400 hover:text-blue-500 transition-colors"
              >
                <span class="iconify" data-icon="hugeicons:comment-01"></span>
                45
              </button>
            </div>
            <span class="text-[10px] text-gray-300">2026-03-14</span>
          </div>
        </div>

        <!-- Review 3 -->
        <div class="p-8 bg-white border border-gray-100 rounded-3xl shadow-sm hover:shadow-xl transition-shadow group">
          <div class="flex items-center gap-3 mb-6">
            <img
              alt="Review User"
              class="w-10 h-10 rounded-full object-cover"
              src="https://modao.cc/agent-py/media/generated_images/2026-03-16/33197687e1cd42adbbc443b37811ad63.jpg"
            />
            <div>
              <p class="text-sm font-bold">孤独的阅读者</p>
              <p class="text-[10px] text-gray-400">点评了《百年孤独》</p>
            </div>
          </div>
          <p class="text-sm leading-relaxed text-gray-600 mb-6 italic">
            “无论何时翻开，马孔多的风雨总能在现实中吹遍我的房间。这是关于宿命最深刻的交响曲。”
          </p>
          <div class="flex items-center justify-between">
            <div class="flex gap-4">
              <button
                class="flex items-center gap-1 text-xs text-gray-400 hover:text-red-500 transition-colors"
              >
                <span class="iconify" data-icon="hugeicons:favourite"></span>
                2.4k
              </button>
              <button
                class="flex items-center gap-1 text-xs text-gray-400 hover:text-blue-500 transition-colors"
              >
                <span class="iconify" data-icon="hugeicons:comment-01"></span>
                312
              </button>
            </div>
            <span class="text-[10px] text-gray-300">2026-03-13</span>
          </div>
        </div>
      </div>
    </section>

    <!-- 7. 页脚区域 -->
    <footer class="bg-white border-t border-gray-100 pt-20 pb-10 px-6">
      <div class="max-w-[1440px] mx-auto">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-12 mb-20">
          <div class="lg:col-span-2">
            <h2 class="text-2xl font-bold serif mb-6 tracking-tighter flex items-center gap-2">
              <span class="inline-block w-8 h-8 bg-black text-white text-center leading-8 rounded-sm">墨</span>
              雅筑
            </h2>
            <p class="text-sm text-gray-400 max-w-sm mb-8 leading-relaxed">
              基于 AI 驱动的 2026 智慧图书发现引擎。无论你是寻求深夜的慰藉，还是理性的升华，我们都为你准备好了通往异世界的书架。
            </p>
            <div class="flex gap-4">
              <a
                href="#"
                class="w-8 h-8 rounded-full border flex items-center justify-center text-gray-400 hover:bg-black hover:text-white transition-all"
              >
                <span class="iconify" data-icon="brandico:weibo"></span>
              </a>
              <a
                href="#"
                class="w-8 h-8 rounded-full border flex items-center justify-center text-gray-400 hover:bg黑 hover:text-white transition-all"
              >
                <span class="iconify" data-icon="hugeicons:square-arrow-up-right"></span>
              </a>
              <a
                href="#"
                class="w-8 h-8 rounded-full border flex items-center justify-center text-gray-400 hover:bg-black hover:text-white transition-all"
              >
                <span class="iconify" data-icon="hugeicons:mail-01"></span>
              </a>
            </div>
          </div>

          <div>
            <h5 class="font-bold text-sm mb-6">探索发现</h5>
            <ul class="space-y-4 text-xs text-gray-500">
              <li><a href="#" class="hover:text-black">年度必读榜单</a></li>
              <li><a href="#" class="hover:text黑">精选专题库</a></li>
              <li><a href="#" class="hover:text-black">出版社合作专区</a></li>
              <li><a href="#" class="hover:text-black">获奖作品集</a></li>
            </ul>
          </div>
          <div>
            <h5 class="font-bold text-sm mb-6">产品服务</h5>
            <ul class="space-y-4 text-xs text-gray-500">
              <li><a href="#" class="hover:text-black">墨香阅读器 APP</a></li>
              <li><a href="#" class="hover:text-black">Premium 会员</a></li>
              <li><a href="#" class="hover:text-black">个人知识图谱</a></li>
              <li><a href="#" class="hover:text-black">开发者接口</a></li>
            </ul>
          </div>
          <div>
            <h5 class="font-bold text-sm mb-6">关于我们</h5>
            <ul class="space-y-4 text-xs text-gray-500">
              <li><a href="#" class="hover:text-black">品牌故事</a></li>
              <li><a href="#" class="hover:text-black">版权声明</a></li>
              <li><a href="#" class="hover:text-black">联系我们</a></li>
              <li><a href="#" class="hover:text-black">加入我们</a></li>
            </ul>
          </div>
        </div>
        <div class="flex flex-col md:flex-row items-center justify-between gap-6 border-t border-gray-50 pt-10">
          <p class="text-[10px] text-gray-400 uppercase tracking-widest">
            © 2026 INK & AMBIENCE. ALL RIGHTS RESERVED. 沪ICP备20260316号
          </p>
          <div class="flex items-center gap-6">
            <button class="flex items-center gap-2 text-xs text-gray-400 hover:text-black">
              <span class="iconify" data-icon="hugeicons:moon-02"></span>
              深色模式
            </button>
            <button class="flex items-center gap-2 text-xs text-gray-400 hover:text-black">
              <span class="iconify" data-icon="hugeicons:globe-01"></span>
              简体中文
            </button>
          </div>
        </div>
      </div>
    </footer>

    <!-- 底部固定移动端 Tab Bar -->
    <div
      class="md:hidden fixed bottom-6 left-6 right-6 h-16 bg-black/90 backdrop-blur-md rounded-full flex items-center justify-around px-8 z-50 border border-white/10 shadow-2xl"
    >
      <a href="#" class="text-white">
        <span class="iconify text-xl" data-icon="hugeicons:home-02"></span>
      </a>
      <a href="#" class="text-gray-400">
        <span class="iconify text-xl" data-icon="hugeicons:book-02"></span>
      </a>
      <a href="#" class="text-gray-400">
        <span class="iconify text-xl" data-icon="hugeicons:discovery-01"></span>
      </a>
      <a href="#" class="text-gray-400">
        <span class="iconify text-xl" data-icon="hugeicons:user-circle"></span>
      </a>
    </div>
  </div>
</template>

