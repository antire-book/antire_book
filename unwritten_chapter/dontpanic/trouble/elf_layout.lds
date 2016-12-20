SECTIONS
{
    mmap_space_size = SIZEOF(.mmap_space);
    start_thread_size = SIZEOF(.start_thread);

    launch_thread_size = SIZEOF(.launch_thread);
    valid_target_size = SIZEOF(.valid_target);
}
